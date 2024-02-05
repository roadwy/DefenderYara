
rule Trojan_Win32_SmokeLoader_C_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {d3 ea 03 c7 03 55 d8 33 d0 31 55 f8 8b 45 f8 29 45 ec 8b 45 e0 29 45 f4 ff 4d e4 0f 85 f2 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_C_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {f7 ff 8b 45 08 0f be 04 10 69 c0 } //02 00 
		$a_03_1 = {03 ce 8b 55 0c 03 55 90 01 01 88 0a 0f be 45 90 01 01 8b 4d 0c 03 4d 90 01 01 0f b6 11 2b d0 8b 45 0c 03 45 90 01 01 88 10 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}