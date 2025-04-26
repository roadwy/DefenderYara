
rule Trojan_Linux_Mirai_X_MTB{
	meta:
		description = "Trojan:Linux/Mirai.X!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {2d 72 20 2f 76 69 2f 6d 69 70 73 2e 62 75 73 68 69 64 6f } //5 -r /vi/mips.bushido
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f } //5 /bin/busybox chmod 777 * /tmp/
		$a_00_2 = {50 4f 53 54 20 2f 63 74 72 6c 74 2f 44 65 76 69 63 65 55 70 67 72 61 64 65 5f 31 20 48 54 54 50 2f 31 2e 31 } //1 POST /ctrlt/DeviceUpgrade_1 HTTP/1.1
		$a_00_3 = {6c 6f 61 64 55 52 4c 3e 24 28 65 63 68 6f 20 48 55 41 57 45 49 55 50 4e 50 29 3c 2f 4e 65 77 44 6f 77 6e 6c 6f 61 64 55 52 4c 3e 3c 2f 75 3a 55 70 67 72 61 64 65 3e 3c 2f 73 3a 42 6f 64 79 3e 3c 2f 73 3a 45 6e 76 65 6c 6f 70 65 3e } //1 loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>
		$a_00_4 = {50 4f 53 54 20 2f 63 64 6e 2d 63 67 69 2f } //1 POST /cdn-cgi/
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}