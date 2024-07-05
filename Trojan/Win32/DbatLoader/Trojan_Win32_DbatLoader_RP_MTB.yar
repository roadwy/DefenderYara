
rule Trojan_Win32_DbatLoader_RP_MTB{
	meta:
		description = "Trojan:Win32/DbatLoader.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4e 63 32 35 90 01 05 5e 5e 4e 63 32 50 32 3e 5b 60 5d 23 32 50 32 3e 5b 60 5d 24 32 50 32 5a 66 66 62 65 2c 21 21 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}