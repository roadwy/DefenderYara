
rule Trojan_Win32_Vidar_DF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 8d 34 0f 8a 0e 88 4d ff 8a 4d fe d2 45 ff 8a 4d 10 2a cb 32 4d ff fe c3 88 0e 3a d8 75 90 01 01 32 db fe c2 88 55 fe 3a 55 fd 75 90 01 01 32 d2 88 55 fe 47 3b 7d 0c 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}