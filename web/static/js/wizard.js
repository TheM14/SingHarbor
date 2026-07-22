/* Protocol deployment wizard with typed fields and public endpoint variants. */

(function () {
  'use strict';

  const state = {protocol: '', schema: null, defaults: {}};
  const text = window.WIZARD_I18N || {};
  const select = document.getElementById('protocol-select');
  const form = document.getElementById('proto-form');

  function setStep(index) {
    document.querySelectorAll('.wizard-step').forEach((step, i) => {
      step.classList.toggle('active', i <= index);
    });
  }

  function fieldValue(name, fallback) {
    return state.defaults[name] !== undefined ? state.defaults[name] : fallback;
  }

  function addProtocolField(container, field) {
    const group = document.createElement('div');
    group.className = 'form-group';
    group.dataset.fieldName = field.name;
    const label = document.createElement('label');
    label.htmlFor = `field-${field.name}`;
    label.textContent = field.name === 'listen_port'
      ? (text.direct_listen_port || 'Direct listen port')
      : field.name;
    if (field.required) {
      const required = document.createElement('span');
      required.className = 'text-err';
      required.textContent = ' *';
      label.appendChild(required);
    }
    group.appendChild(label);

    const value = fieldValue(field.name, field.default === null ? '' : field.default);
    let input;
    if (field.type === 'bool') {
      const row = document.createElement('label');
      row.className = 'check-row';
      input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = value === true || String(value).toLowerCase() === 'true';
      const caption = document.createElement('span');
      caption.textContent = field.description || field.name;
      row.append(input, caption);
      group.replaceChildren(row);
    } else if (field.choices) {
      input = document.createElement('select');
      field.choices.forEach((choice) => {
        const option = document.createElement('option');
        option.value = String(choice);
        option.textContent = String(choice || 'Default');
        option.selected = String(choice) === String(value);
        input.appendChild(option);
      });
    } else {
      input = document.createElement('input');
      input.type = field.type === 'int' ? 'number' :
        ['password', 'secret'].includes(field.type) ? 'password' : 'text';
      input.value = value === undefined || value === null ? '' : String(value);
      if (field.min !== null && field.min !== undefined) input.min = field.min;
      if (field.max !== null && field.max !== undefined) input.max = field.max;
      if (field.required) input.required = true;
      input.autocomplete = ['password', 'secret'].includes(field.type) ? 'new-password' : 'off';
    }
    input.id = `field-${field.name}`;
    input.name = field.name;
    input.dataset.fieldType = field.type;
    if (field.type !== 'bool') group.appendChild(input);

    if (field.description && field.type !== 'bool') {
      const help = document.createElement('div');
      help.className = 'form-help';
      help.textContent = field.description;
      group.appendChild(help);
    }
    container.appendChild(group);
  }

  function setNamedValue(name, value) {
    const input = form.elements.namedItem(name);
    if (!input) return;
    if (input.type === 'checkbox') input.checked = !!value;
    else input.value = value === undefined || value === null ? '' : String(value);
  }

  function loadConnectionDefaults(supportsCloudflare) {
    ['public_ipv4', 'public_ipv6', 'public_domain', 'preferred_endpoint',
      'cloudflare_preferred_ip',
      'ws_enabled', 'ws_path', 'tls_enabled', 'tls_server_name',
      'tls_certificate_path', 'tls_key_path', 'cloudflare_proxied',
      'cdn_listen_port'
    ].forEach((name) => setNamedValue(name, state.defaults[name]));

    const cdn = document.getElementById('cdn-options');
    cdn.hidden = !supportsCloudflare;
    document.getElementById('cf-proxied').disabled = !supportsCloudflare;
    if (!supportsCloudflare) document.getElementById('cf-proxied').checked = false;
    if (supportsCloudflare && document.getElementById('cf-proxied').checked) {
      document.getElementById('ws-enabled').checked = true;
      document.getElementById('tls-enabled').checked = true;
    }
    toggleCloudflareFields();
    toggleTlsFields();
  }

  async function initProtocols() {
    try {
      const result = await API.get('/api/protocols');
      result.protocols.forEach((protocol) => {
        const option = document.createElement('option');
        option.value = protocol.type;
        option.textContent = `${protocol.name} (${protocol.type})`;
        select.appendChild(option);
      });
      const requested = new URLSearchParams(window.location.search).get('type');
      if (requested) {
        select.value = requested;
        await loadProtocolForm();
      }
    } catch (error) {
      API.flash(error.message);
    }
  }

  async function loadProtocolForm() {
    const protocolType = select.value;
    if (!protocolType) return;
    state.protocol = protocolType;
    document.getElementById('form-errors').textContent = '';
    try {
      const [schemaResult, defaultsResult] = await Promise.all([
        API.get(`/api/protocols/${encodeURIComponent(protocolType)}`),
        API.get(`/api/protocols/${encodeURIComponent(protocolType)}/defaults`),
      ]);
      state.schema = schemaResult.protocol;
      state.defaults = defaultsResult.defaults || {};
      const container = document.getElementById('proto-fields');
      container.replaceChildren();
      state.schema.fields.forEach((field) => addProtocolField(container, field));

      const tagGroup = document.createElement('div');
      tagGroup.className = 'form-group';
      const tagLabel = document.createElement('label');
      tagLabel.htmlFor = 'field-tag';
      tagLabel.textContent = 'tag';
      const tagInput = document.createElement('input');
      tagInput.id = 'field-tag';
      tagInput.name = 'tag';
      tagInput.value = state.defaults.tag || `${protocolType}-in`;
      tagGroup.append(tagLabel, tagInput);
      container.appendChild(tagGroup);

      loadConnectionDefaults(!!state.schema.supports_cloudflare_ws);
      setupRealityFields();
      document.getElementById('step-configure').hidden = false;
      document.getElementById('step-preview').hidden = true;
      document.getElementById('step-result').hidden = true;
      setStep(1);
    } catch (error) {
      API.flash(error.message);
    }
  }

  function collectParams() {
    const params = {};
    form.querySelectorAll('[name]').forEach((input) => {
      if (input.disabled) return;
      if (input.type === 'checkbox') params[input.name] = input.checked;
      else if (input.dataset.fieldType === 'int' || input.type === 'number') {
        params[input.name] = input.value === '' ? 0 : Number.parseInt(input.value, 10);
      } else params[input.name] = input.value.trim();
    });
    return params;
  }

  function showError(error) {
    const errors = error.data && error.data.errors;
    document.getElementById('form-errors').textContent = errors ? errors.join(' · ') : error.message;
  }

  function copyValue(value) {
    navigator.clipboard.writeText(value).then(
      () => API.flash(text.copied || 'Copied'),
      () => API.flash('Copy failed')
    );
  }

  function renderClientVariants(clientInfo) {
    const wrapper = document.createElement('div');
    const heading = document.createElement('h3');
    heading.textContent = text.client_connection || 'Client connection';
    wrapper.appendChild(heading);

    const variants = clientInfo && clientInfo.variants ? clientInfo.variants : [];
    if (!variants.length) {
      const note = document.createElement('p');
      note.className = 'field-note';
      note.textContent = text.no_public_endpoint || 'Configure a public endpoint to generate client links.';
      wrapper.appendChild(note);
      return wrapper;
    }

    const grid = document.createElement('div');
    grid.className = 'endpoint-grid';
    variants.forEach((variant) => {
      const card = document.createElement('article');
      card.className = 'endpoint-card';
      const title = document.createElement('div');
      title.className = 'endpoint-title';
      const name = document.createElement('strong');
      name.textContent = variant.label;
      const badge = document.createElement('span');
      badge.className = `badge ${variant.cloudflare_proxied ? 'badge-ok' : ''}`;
      badge.textContent = variant.cloudflare_proxied ? 'Cloudflare' : variant.kind.toUpperCase();
      title.append(name, badge);
      card.appendChild(title);

      const address = document.createElement('code');
      address.textContent = variant.address;
      card.appendChild(address);
      const actions = document.createElement('div');
      actions.className = 'endpoint-actions';
      if (variant.share_link) {
        const copyLink = document.createElement('button');
        copyLink.type = 'button';
        copyLink.className = 'btn btn-sm';
        copyLink.textContent = `${text.copy || 'Copy'} ${text.share_link || 'link'}`;
        copyLink.addEventListener('click', () => copyValue(variant.share_link));
        actions.appendChild(copyLink);
      }
      const copyJson = document.createElement('button');
      copyJson.type = 'button';
      copyJson.className = 'btn btn-sm';
      copyJson.textContent = `${text.copy || 'Copy'} JSON`;
      copyJson.addEventListener('click', () => copyValue(JSON.stringify(variant.config_snippet, null, 2)));
      actions.appendChild(copyJson);
      card.appendChild(actions);
      const details = document.createElement('details');
      const summary = document.createElement('summary');
      summary.textContent = 'Client JSON';
      const pre = document.createElement('pre');
      pre.textContent = JSON.stringify(variant.config_snippet, null, 2);
      details.append(summary, pre);
      card.appendChild(details);
      grid.appendChild(card);
    });
    wrapper.appendChild(grid);
    return wrapper;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = document.getElementById('btn-deploy');
    setLoading(button);
    document.getElementById('form-errors').textContent = '';
    try {
      const result = await API.post('/api/protocols/deploy', {
        type: state.protocol,
        params: collectParams(),
        restart: true,
      });
      const resultSection = document.getElementById('step-result');
      const output = document.getElementById('deploy-result');
      output.replaceChildren();
      const status = document.createElement('p');
      status.className = result.success ? 'text-ok' : 'text-err';
      status.textContent = result.message || (text.deployment_success || 'Deployment successful');
      const inboundTitle = document.createElement('h3');
      inboundTitle.textContent = text.generated_inbounds || 'Generated inbounds';
      const inbound = document.createElement('pre');
      inbound.textContent = JSON.stringify(result.inbounds || [result.inbound], null, 2);
      output.append(status, inboundTitle, inbound, renderClientVariants(result.client_info));
      resultSection.hidden = false;
      setStep(2);
      resultSection.scrollIntoView({behavior: 'smooth', block: 'start'});
    } catch (error) {
      showError(error);
    } finally {
      resetLoading(button);
    }
  });

  async function previewConfig() {
    const button = document.getElementById('btn-preview');
    setLoading(button);
    document.getElementById('form-errors').textContent = '';
    try {
      const result = await API.post('/api/protocols/preview', {
        type: state.protocol,
        params: collectParams(),
      });
      document.getElementById('preview-content').textContent = JSON.stringify(result.preview, null, 2);
      document.getElementById('diff-content').textContent = JSON.stringify(result.diff, null, 2);
      document.getElementById('step-preview').hidden = false;
    } catch (error) {
      showError(error);
    } finally {
      resetLoading(button);
    }
  }

  function toggleTlsFields() {
    document.getElementById('tls-fields').hidden = !document.getElementById('tls-enabled').checked;
  }

  function toggleCloudflareFields() {
    const enabled = document.getElementById('cf-proxied').checked;
    document.getElementById('cf-preferred-ip-group').hidden = !enabled;
    document.getElementById('wizard-cf-preferred-ip').disabled = !enabled;
  }

  function setupRealityFields() {
    const toggle = form.elements.namedItem('reality_enabled');
    const realityGroups = document.querySelectorAll(
      '#proto-fields [data-field-name^="reality_"]:not([data-field-name="reality_enabled"])'
    );
    if (!toggle) {
      realityGroups.forEach((group) => { group.hidden = true; });
      return;
    }
    const update = () => {
      const enabled = toggle.checked;
      realityGroups.forEach((group) => { group.hidden = !enabled; });
      const cloudflare = document.getElementById('cf-proxied');
      const websocket = document.getElementById('ws-enabled');
      const tls = document.getElementById('tls-enabled');
      cloudflare.disabled = enabled || !state.schema.supports_cloudflare_ws;
      websocket.disabled = enabled;
      tls.disabled = enabled;
      if (enabled) {
        cloudflare.checked = false;
        websocket.checked = false;
        tls.checked = false;
        const flow = form.elements.namedItem('flow');
        if (flow && !flow.value) flow.value = 'xtls-rprx-vision';
      }
      toggleCloudflareFields();
      toggleTlsFields();
    };
    toggle.addEventListener('change', update);
    update();
  }

  document.getElementById('tls-enabled').addEventListener('change', toggleTlsFields);
  document.getElementById('cf-proxied').addEventListener('change', function () {
    toggleCloudflareFields();
    if (!this.checked) return;
    document.getElementById('ws-enabled').checked = true;
    document.getElementById('tls-enabled').checked = true;
    toggleTlsFields();
    const cdnPort = form.elements.namedItem('cdn_listen_port');
    if (cdnPort && ![443, 2053, 2083, 2087, 2096, 8443].includes(Number(cdnPort.value))) {
      cdnPort.value = 443;
    }
    document.getElementById('wizard-preferred').value = 'domain';
    const domain = document.getElementById('wizard-domain').value;
    if (domain && !document.getElementById('tls-server-name').value) {
      document.getElementById('tls-server-name').value = domain;
    }
  });
  document.getElementById('wizard-domain').addEventListener('input', function () {
    const sni = document.getElementById('tls-server-name');
    if (!sni.dataset.edited) sni.value = this.value;
  });
  document.getElementById('tls-server-name').addEventListener('input', function () {
    this.dataset.edited = 'true';
  });
  document.getElementById('btn-next').addEventListener('click', loadProtocolForm);
  document.getElementById('btn-preview').addEventListener('click', previewConfig);
  initProtocols();
})();
