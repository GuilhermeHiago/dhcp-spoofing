# DHCP Spoofing
dhcp spoofing in c using raw sockets.

TODO
- [X] Enviar pacotes DHCP.
    - [X] Enviar pacote UDP (Já testado e funcionando). Por padrão envia por PORT src = 67 (servidor), para PORT dst = 68 (client).
    - [X] Enviar pacote DHCP - (foi necessario um ponteiro que apontasse para o inicio do dhcp no buffer - tipo struct *dhcp).
        - [X] o xid deve ser o mesmo recebido em src do discovery.
        - [X] o MAC deve ser o mesmo recebido em src do discovery.

- [X] Recever pacotes DHCP.
    - [X] Receber e filtrar apenas pacotes DHCP (discover e request).
