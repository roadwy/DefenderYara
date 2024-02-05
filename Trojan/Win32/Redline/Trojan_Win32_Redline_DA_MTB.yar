
rule Trojan_Win32_Redline_DA_MTB{
	meta:
		description = "Trojan:Win32/Redline.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 90 01 04 19 36 6b ff 89 45 0c 8b 45 d8 01 45 0c ff 75 f4 8d 45 f0 50 e8 90 01 04 8b 45 0c 31 45 f0 8b 45 f0 29 45 f8 83 65 fc 00 8b 45 d4 01 45 fc 2b 55 fc ff 4d e8 8b 45 f8 89 55 ec 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}