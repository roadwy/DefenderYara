
rule Trojan_Win32_Zusy_RE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 6f 72 6b 38 2e 64 6c 6c 00 4a 69 61 6a 6f 69 66 6a 61 65 67 65 61 69 6a 67 64 6a 00 4c 61 69 6f 66 67 6a 61 65 6f 69 67 65 61 67 68 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 8b 08 89 4d e8 8b 55 f4 8b 02 c1 e0 06 8b 4d f4 8b 11 c1 ea 08 33 c2 8b 4d f4 8b 09 03 c8 8b 45 fc 33 d2 f7 75 ec 8b 45 08 03 0c 90 03 4d fc 8b 55 f0 8b 02 2b c1 8b 4d f0 89 01 } //00 00 
	condition:
		any of ($a_*)
 
}