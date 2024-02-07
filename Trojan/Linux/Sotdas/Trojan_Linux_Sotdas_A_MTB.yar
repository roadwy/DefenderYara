
rule Trojan_Linux_Sotdas_A_MTB{
	meta:
		description = "Trojan:Linux/Sotdas.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 65 74 63 2f 69 6e 69 74 2e 64 2f 69 70 74 61 62 6c 65 73 20 73 74 6f 70 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c } //01 00  /etc/init.d/iptables stop > /dev/null
		$a_00_1 = {72 65 53 75 53 45 66 69 72 65 77 61 6c 6c 32 20 73 74 6f 70 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c } //01 00  reSuSEfirewall2 stop > /dev/null
		$a_00_2 = {75 66 77 20 64 69 73 61 62 6c 65 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c } //01 00  ufw disable > /dev/null
		$a_02_3 = {6e 65 74 73 74 61 74 20 2d 61 6e 70 20 7c 20 67 72 65 70 90 02 05 3a 90 02 06 7c 61 77 6b 20 27 7b 70 72 69 6e 74 20 24 4e 46 7d 27 20 7c 63 75 74 20 2d 64 90 02 15 78 61 72 67 73 20 6b 69 6c 6c 20 2d 39 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 3b 66 72 65 65 20 2d 6d 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 90 00 } //01 00 
		$a_00_4 = {63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 67 63 6f 6e 66 64 2e 62 69 6e } //01 00  chmod 777 /tmp/gconfd.bin
		$a_00_5 = {6c 6e 20 2d 73 20 2f 65 74 63 2f 69 6e 69 74 2e 64 2f 25 73 20 2f 65 74 63 2f 72 63 32 2e 64 2f 53 37 37 25 73 } //00 00  ln -s /etc/init.d/%s /etc/rc2.d/S77%s
	condition:
		any of ($a_*)
 
}