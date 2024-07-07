
rule Trojan_Win32_Stealerc_AMMB_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 31 00 37 00 32 00 2e 00 31 00 32 00 38 00 2e 00 39 00 30 00 2f 00 63 00 70 00 61 00 2f 00 70 00 69 00 6e 00 67 00 2e 00 70 00 68 00 70 00 } //2 http://185.172.128.90/cpa/ping.php
		$a_80_1 = {2f 53 49 4c 45 4e 54 } ///SILENT  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}