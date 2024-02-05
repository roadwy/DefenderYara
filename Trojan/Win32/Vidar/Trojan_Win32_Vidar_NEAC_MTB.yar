
rule Trojan_Win32_Vidar_NEAC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b c6 f7 f1 8b 85 f0 fd ff ff 8a 0c 02 8b 95 ec fd ff ff 32 0c 3a 8d 85 f4 fd ff ff 50 88 0f } //02 00 
		$a_01_1 = {45 78 6f 64 75 73 20 57 65 62 33 20 57 61 6c 6c 65 74 } //02 00 
		$a_01_2 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 46 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}