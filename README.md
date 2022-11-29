# DHCP Spoofing
dhcp spoofing in c using raw sockets.

TODO
- [ ] Enviar pacotes DHCP.
    - [X] Enviar pacote UDP (Já testado e funcionando). Por padrão envia por PORT src = 67 (servidor), para PORT dst = 68 (client).
    - [X] Enviar pacote DHCP - Valores não estão salvando na posição correta VERIFICAR MONTAGEM DO PACOTE.
    - [ ] Enviar pacote DHCP - o xid deve ser o mesmo do recebido.

- [ ] Recever pacotes DHCP.
    - [ ] Receber e filtrar apenas pacotes DHCP (discover e request).
