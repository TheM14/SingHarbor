/* Inbound management, client export, QR codes, and in-place JSON editing. */

(function () {
  'use strict';

  const text = window.INBOUNDS_I18N || {};
  const list = document.getElementById('inbounds-list');
  const dialog = document.getElementById('inbound-edit-dialog');
  let exportCache = null;
  let inboundsCache = [];

  function cellRow(label, value) {
    const row = document.createElement('tr');
    const key = document.createElement('td');
    const content = document.createElement('td');
    key.textContent = label;
    content.textContent = value;
    row.append(key, content);
    return row;
  }

  function copyValue(value) {
    return navigator.clipboard.writeText(value).then(
      () => API.flash(text.copied || 'Copied'),
      () => API.flash('Copy failed')
    );
  }

  function button(label, className, handler) {
    const element = document.createElement('button');
    element.type = 'button';
    element.className = className || 'btn btn-sm';
    element.textContent = label;
    element.addEventListener('click', handler);
    return element;
  }

  async function showQr(container, value) {
    let image = container.querySelector('.share-qr');
    if (image) {
      image.hidden = !image.hidden;
      return;
    }
    const result = await API.post('/api/tools/qr', {value});
    image = document.createElement('img');
    image.className = 'share-qr';
    image.src = result.data_url;
    image.alt = text.qr_code || 'QR code';
    container.appendChild(image);
  }

  function renderVariant(option) {
    const card = document.createElement('div');
    card.className = 'endpoint-card';
    const title = document.createElement('div');
    title.className = 'endpoint-title';
    const name = document.createElement('strong');
    name.textContent = option.label;
    const badge = document.createElement('span');
    badge.className = `badge ${option.cloudflare_proxied ? 'badge-ok' : ''}`;
    badge.textContent = option.cloudflare_proxied ? 'Cloudflare' : option.kind.toUpperCase();
    title.append(name, badge);
    const address = document.createElement('code');
    address.textContent = option.address;
    const actions = document.createElement('div');
    actions.className = 'endpoint-actions';
    const revealed = document.createElement('code');
    revealed.className = 'revealed-link';
    revealed.hidden = true;

    if (option.share_link) {
      const revealButton = button(text.reveal || 'Reveal', 'btn btn-sm', () => {
        revealed.hidden = !revealed.hidden;
        revealButton.textContent = revealed.hidden
          ? (text.reveal || 'Reveal')
          : (text.hide || 'Hide');
      });
      actions.append(
        revealButton,
        button(`${text.copy || 'Copy'} Link`, 'btn btn-sm', () => copyValue(option.share_link)),
        button(text.qr_code || 'QR code', 'btn btn-sm', () => showQr(card, option.share_link))
      );
      revealed.textContent = option.share_link;
    }
    actions.append(button(
      text.client_json || 'Client JSON',
      'btn btn-sm',
      () => copyValue(JSON.stringify(option.config_snippet, null, 2))
    ));
    card.append(title, address, actions, revealed);
    return card;
  }

  function renderInbound(inbound) {
    const card = document.createElement('article');
    card.className = 'card';
    const heading = document.createElement('div');
    heading.className = 'card-title-row';
    const title = document.createElement('h3');
    title.textContent = inbound.tag;
    const status = document.createElement('span');
    status.className = `badge ${inbound.running ? 'badge-ok' : 'badge-warn'}`;
    status.textContent = inbound.running ? (text.running || 'Running') : (text.stopped || 'Stopped');
    heading.append(title, status);

    const table = document.createElement('table');
    table.className = 'info-table';
    table.append(
      cellRow(text.protocol || 'Protocol', inbound.type),
      cellRow(text.listen || 'Listen', `${inbound.listen}:${inbound.listen_port}`),
      cellRow(text.tls || 'TLS', inbound.tls && inbound.tls.enabled ? (text.enabled || 'Enabled') : (text.disabled || 'Disabled')),
      cellRow(text.transport || 'Transport', inbound.transport ? inbound.transport.type : 'tcp'),
      cellRow(text.users || 'Users', String(inbound.user_count))
    );
    if (!inbound.recognized) {
      table.appendChild(cellRow('', text.not_recognized || 'Not fully recognized'));
    }

    card.append(heading, table);
    if (inbound.client_options && inbound.client_options.length) {
      const grid = document.createElement('div');
      grid.className = 'endpoint-grid';
      inbound.client_options.forEach((option) => grid.appendChild(renderVariant(option)));
      card.appendChild(grid);
    } else {
      const note = document.createElement('div');
      note.className = 'field-note';
      note.textContent = text.no_endpoint || 'No public endpoint configured.';
      card.appendChild(note);
    }

    const actions = document.createElement('div');
    actions.className = 'endpoint-actions card-actions';
    actions.append(
      button(text.edit || 'Edit', 'btn btn-sm', () => openEditor(inbound.tag)),
      button(text.delete || 'Delete', 'btn btn-sm btn-warn', () => deleteInbound(inbound.tag))
    );
    card.appendChild(actions);
    return card;
  }

  async function loadInbounds() {
    try {
      const result = await API.get('/api/inbounds');
      exportCache = null;
      inboundsCache = result.inbounds || [];
      list.replaceChildren();
      if (!inboundsCache.length) {
        list.textContent = text.no_inbounds || 'No inbounds configured.';
        return;
      }
      inboundsCache.forEach((inbound) => list.appendChild(renderInbound(inbound)));
    } catch (error) {
      list.textContent = error.message;
    }
  }

  async function deleteInbound(tag) {
    if (!confirmAction(text.confirm_delete || 'Delete this inbound?')) return;
    try {
      await API.del(`/api/inbounds/${encodeURIComponent(tag)}`);
      await loadInbounds();
    } catch (error) {
      API.flash(error.message);
    }
  }

  async function openEditor(tag) {
    try {
      const result = await API.get(`/api/inbounds/${encodeURIComponent(tag)}/edit`);
      document.getElementById('edit-original-tag').value = tag;
      document.getElementById('edit-inbound-json').value = JSON.stringify(result.inbound, null, 2);
      document.getElementById('edit-endpoint-profile').value = JSON.stringify(result.endpoint_profile, null, 2);
      document.getElementById('edit-inbound-error').textContent = '';
      if (dialog.showModal) dialog.showModal();
      else dialog.setAttribute('open', '');
    } catch (error) {
      API.flash(error.message);
    }
  }

  async function getExport() {
    if (exportCache) return exportCache;
    try {
      exportCache = await API.get('/api/inbounds/export');
    } catch (error) {
      if (!inboundsCache.length) throw error;
      exportCache = buildLocalExport(inboundsCache);
    }
    return exportCache;
  }

  function buildLocalExport(inbounds) {
    const exportedInbounds = [];
    const items = [];
    const sections = [];
    inbounds.forEach((inbound) => {
      const variants = (inbound.client_options || []).map((option) => {
        const clientConfig = option.config_snippet || {};
        const shareLink = option.share_link || '';
        const item = {
          inbound_tag: inbound.tag,
          protocol: inbound.type,
          kind: option.kind || '',
          label: option.label || '',
          address: option.address || '',
          domain: option.domain || '',
          share_link: shareLink,
          client_config: clientConfig,
          portable_value: shareLink || JSON.stringify(clientConfig, null, 2),
        };
        items.push(item);
        sections.push(`# ${item.inbound_tag} / ${item.label}\n${item.portable_value}`);
        return item;
      });
      exportedInbounds.push({
        tag: inbound.tag,
        protocol: inbound.type,
        recognized: Boolean(inbound.recognized),
        variants,
      });
    });
    return {
      format: 'singharbor-client-export',
      version: 1,
      generated_at: new Date().toISOString(),
      inbounds: exportedInbounds,
      items,
      text: sections.join('\n\n'),
    };
  }

  function download(filename, content, type) {
    const url = URL.createObjectURL(new Blob([content], {type}));
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function runExportAction(buttonId, action) {
    const trigger = document.getElementById(buttonId);
    setLoading(trigger);
    try {
      const result = await getExport();
      if (!result.items.length) {
        API.flash(text.export_empty || 'Nothing to export');
        return;
      }
      await action(result);
    } catch (error) {
      API.flash(error.message || String(error));
    } finally {
      resetLoading(trigger);
    }
  }

  document.getElementById('copy-all-clients').addEventListener('click', () => {
    runExportAction('copy-all-clients', (result) => copyValue(result.text));
  });
  document.getElementById('download-client-text').addEventListener('click', () => {
    runExportAction('download-client-text', (result) => {
      download('singharbor-clients.txt', result.text, 'text/plain;charset=utf-8');
    });
  });
  document.getElementById('download-client-export').addEventListener('click', () => {
    runExportAction('download-client-export', (result) => {
      download('singharbor-client-export.json', JSON.stringify(result, null, 2), 'application/json');
    });
  });
  document.getElementById('close-inbound-editor').addEventListener('click', () => dialog.close());
  document.getElementById('inbound-edit-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const submit = document.getElementById('save-inbound-edit');
    const errorBox = document.getElementById('edit-inbound-error');
    errorBox.textContent = '';
    let inbound;
    let endpointProfile;
    try {
      inbound = JSON.parse(document.getElementById('edit-inbound-json').value);
      endpointProfile = JSON.parse(document.getElementById('edit-endpoint-profile').value);
    } catch (error) {
      errorBox.textContent = error.message;
      return;
    }
    setLoading(submit);
    try {
      const tag = document.getElementById('edit-original-tag').value;
      const result = await API.put(`/api/inbounds/${encodeURIComponent(tag)}`, {
        inbound,
        endpoint_profile: endpointProfile,
        restart: document.getElementById('edit-restart').checked,
      });
      dialog.close();
      API.flash(result.warning || text.saved || 'Saved');
      await loadInbounds();
    } catch (error) {
      errorBox.textContent = error.message;
    } finally {
      resetLoading(submit);
    }
  });

  loadInbounds();
})();
