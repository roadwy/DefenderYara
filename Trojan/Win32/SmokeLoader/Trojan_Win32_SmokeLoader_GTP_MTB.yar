
rule Trojan_Win32_SmokeLoader_GTP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 c7 05 90 01 04 19 36 6b ff 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 ff 75 90 01 01 8b c3 c1 e0 90 01 01 03 c6 33 45 90 01 01 89 45 90 01 01 8d 45 90 01 01 50 e8 90 01 04 ff 75 90 01 01 8d 45 90 01 01 50 e8 90 01 04 81 45 90 01 01 47 86 c8 61 ff 4d 90 01 01 0f 85 90 00 } //0a 00 
		$a_03_1 = {c1 e8 05 c7 05 90 01 04 19 36 6b ff 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 ff 75 90 01 01 03 f3 33 75 90 01 01 8d 45 90 01 01 50 89 75 90 01 01 e8 90 01 04 ff 75 90 01 01 8d 45 90 01 01 50 e8 90 01 04 81 45 90 01 01 47 86 c8 61 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}