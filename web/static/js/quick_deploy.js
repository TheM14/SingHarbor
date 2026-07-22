/* One-click multi-protocol deployment UI. */

(function () {
  'use strict';

  const text = window.QUICK_DEPLOY_I18N || {};
  const form = document.getElementById('quick-deploy-form');
  const resultSection = document.getElementById('quick-result');
  const letsEncryptToggle = document.getElementById('quick-le-enabled');

  function syncLetsEncryptFields() {
    const enabled = letsEncryptToggle.checked;
    document.getElementById('quick-le-email').required = enabled;
  }

  function copyValue(value) {
    navigator.clipboard.writeText(value).then(
      () => API.flash(text.copied || 'Copied'),
      () => API.flash('Copy failed')
    );
  }

  function makeButton(label, value) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-sm';
    button.textContent = label;
    button.addEventListener('click', () => copyValue(value));
    return button;
  }

  function renderVariant(variant) {
    const card = document.createElement('div');
    card.className = 'quick-variant';
    const title = document.createElement('div');
    title.className = 'endpoint-title';
    const name = document.createElement('strong');
    name.textContent = variant.label;
    const badge = document.createElement('span');
    badge.className = `badge ${variant.cloudflare_proxied ? 'badge-ok' : ''}`;
    badge.textContent = variant.role;
    title.append(name, badge);
    card.appendChild(title);

    const address = document.createElement('code');
    address.textContent = variant.address;
    card.appendChild(address);
    const actions = document.createElement('div');
    actions.className = 'endpoint-actions';
    if (variant.share_link) {
      actions.appendChild(makeButton(text.copy || 'Copy', variant.share_link));
    } else {
      const note = document.createElement('span');
      note.className = 'badge badge-warn';
      note.textContent = text.no_link || 'JSON only';
      actions.appendChild(note);
    }
    actions.appendChild(makeButton(
      text.client_json || 'Client JSON',
      JSON.stringify(variant.config_snippet, null, 2)
    ));
    card.appendChild(actions);
    return card;
  }

  function renderResult(result) {
    const summary = document.getElementById('quick-summary');
    summary.replaceChildren();
    const status = document.createElement('p');
    status.className = result.success ? 'text-ok' : 'text-err';
    status.textContent = result.message;
    summary.appendChild(status);
    (result.warnings || []).forEach((warning) => {
      const note = document.createElement('p');
      note.className = 'field-note';
      note.textContent = warning;
      summary.appendChild(note);
    });
    if (result.certificate) {
      const certificate = result.certificate;
      const card = document.createElement('article');
      card.className = 'endpoint-card';
      const heading = document.createElement('h3');
      heading.textContent = text.certificate_verified || 'Let\'s Encrypt certificate verified';
      card.appendChild(heading);
      const details = [
        [text.certificate_issuer || 'Issuer', certificate.issuer],
        [text.certificate_valid_until || 'Valid until', certificate.not_after],
        [text.certificate_fingerprint || 'SHA-256 fingerprint', certificate.sha256_fingerprint],
        [text.certificate_path || 'Certificate path', certificate.certificate_path],
        [text.certificate_receipt || 'Verification receipt', certificate.receipt_path],
        [text.certificate_inbounds || 'Configured inbounds', (certificate.configured_inbounds || []).join(', ')],
        [text.certificate_dns_auth || 'DNS authentication', `${certificate.dns_authenticator || 'dns-cloudflare'} (${certificate.token_source || 'unknown'})`],
      ];
      details.forEach(([label, value]) => {
        if (!value) return;
        const row = document.createElement('p');
        const strong = document.createElement('strong');
        strong.textContent = `${label}: `;
        const content = document.createElement('code');
        content.textContent = value;
        row.append(strong, content);
        card.appendChild(row);
      });
      summary.appendChild(card);
    }

    const protocolGrid = document.getElementById('quick-protocols');
    protocolGrid.replaceChildren();
    const skipped = [];
    (result.protocols || []).forEach((protocol) => {
      if (protocol.status !== 'planned') {
        skipped.push(protocol);
        return;
      }
      const article = document.createElement('article');
      article.className = 'endpoint-card quick-protocol-card';
      const heading = document.createElement('div');
      heading.className = 'endpoint-title';
      const name = document.createElement('h3');
      name.textContent = protocol.name;
      const roles = document.createElement('span');
      roles.className = 'badge badge-ok';
      roles.textContent = protocol.roles.join(' + ');
      heading.append(name, roles);
      article.appendChild(heading);
      if (protocol.reasons && protocol.reasons.length) {
        const partial = document.createElement('div');
        partial.className = 'field-note';
        partial.textContent = protocol.reasons.join(' ');
        article.appendChild(partial);
      }
      const variants = document.createElement('div');
      variants.className = 'quick-variant-list';
      protocol.variants.forEach((variant) => variants.appendChild(renderVariant(variant)));
      article.appendChild(variants);
      protocolGrid.appendChild(article);
    });

    const skippedSection = document.getElementById('quick-skipped');
    skippedSection.replaceChildren();
    if (skipped.length) {
      const heading = document.createElement('h3');
      heading.textContent = text.skipped || 'Skipped protocols';
      const list = document.createElement('ul');
      skipped.forEach((protocol) => {
        const item = document.createElement('li');
        item.textContent = `${protocol.name}: ${(protocol.reasons || []).join(' ')}`;
        list.appendChild(item);
      });
      skippedSection.append(heading, list);
    }
    resultSection.hidden = false;
    resultSection.scrollIntoView({behavior: 'smooth', block: 'start'});
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    document.getElementById('quick-errors').textContent = '';
    if (!confirmAction(text.confirm || 'Deploy all supported protocols?')) return;
    const button = document.getElementById('quick-deploy-button');
    setLoading(button, text.loading || 'Deploying...');
    const payload = {
      public_domain: document.getElementById('quick-domain').value.trim(),
      cloudflare_preferred_ip: document.getElementById('quick-cf-preferred-ip').value.trim(),
      certificate_directory: document.getElementById('quick-cert-dir').value.trim(),
      lets_encrypt_enabled: letsEncryptToggle.checked,
      lets_encrypt_email: document.getElementById('quick-le-email').value.trim(),
      cloudflare_api_token: document.getElementById('quick-le-token').value.trim(),
      public_ipv4: document.getElementById('quick-ipv4').value.trim(),
      public_ipv6: document.getElementById('quick-ipv6').value.trim(),
      restart: true,
    };
    try {
      renderResult(await API.post('/api/quick-deploy', payload));
    } catch (error) {
      const messages = error.data && error.data.errors;
      document.getElementById('quick-errors').textContent = messages && messages.length
        ? messages.join(' · ') : error.message;
      if (error.data && error.data.protocols) renderResult(error.data);
    } finally {
      document.getElementById('quick-le-token').value = '';
      resetLoading(button);
    }
  });

  API.get('/api/settings').then((settings) => {
    const endpoints = settings.public_endpoints || {};
    document.getElementById('quick-domain').value = endpoints.public_domain || '';
    document.getElementById('quick-cf-preferred-ip').value = endpoints.cloudflare_preferred_ip || '';
    document.getElementById('quick-ipv4').value = endpoints.public_ipv4 || '';
    document.getElementById('quick-ipv6').value = endpoints.public_ipv6 || '';
  }).catch(() => {});
  letsEncryptToggle.addEventListener('change', syncLetsEncryptFields);
  syncLetsEncryptFields();
})();
