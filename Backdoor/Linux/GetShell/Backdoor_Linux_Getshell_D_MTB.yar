
rule Backdoor_Linux_Getshell_D_MTB{
	meta:
		description = "Backdoor:Linux/Getshell.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 73 6f 63 6b 73 35 2e 73 68 } //01 00  /tmp/socks5.sh
		$a_01_1 = {63 61 74 20 3c 28 65 63 68 6f 20 27 40 72 65 62 6f 6f 74 20 65 63 68 6f 20 73 6f 63 6b 73 35 5f 62 61 63 6b 63 6f 6e 6e 65 63 74 36 36 36 } //01 00  cat <(echo '@reboot echo socks5_backconnect666
		$a_01_2 = {2f 73 6f 63 6b 73 35 5f 62 61 63 6b 63 6f 6e 6e 65 63 74 36 36 36 } //01 00  /socks5_backconnect666
		$a_01_3 = {63 72 6f 6e 74 61 62 20 2d 6c 20 32 3e } //00 00  crontab -l 2>
	condition:
		any of ($a_*)
 
}