
rule Trojan_Linux_SuspiciousCron_A{
	meta:
		description = "Trojan:Linux/SuspiciousCron.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 72 00 6f 00 6e 00 74 00 61 00 62 00 20 00 2d 00 6c 00 } //2 crontab -l
		$a_00_1 = {65 00 63 00 68 00 6f 00 20 00 2a 00 2f 00 31 00 20 00 2a 00 20 00 2a 00 20 00 2a 00 20 00 2a 00 20 00 } //2 echo */1 * * * * 
		$a_00_2 = {63 00 72 00 6f 00 6e 00 74 00 61 00 62 00 20 00 2d 00 } //2 crontab -
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}