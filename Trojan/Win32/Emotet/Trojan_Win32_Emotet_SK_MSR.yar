
rule Trojan_Win32_Emotet_SK_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 76 64 66 66 78 63 64 66 73 64 78 78 7a 53 61 77 } //1 cvdffxcdfsdxxzSaw
		$a_01_1 = {53 65 74 46 69 6c 65 53 65 63 75 72 69 74 79 } //1 SetFileSecurity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_SK_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.SK!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 10 88 18 8b 5d f8 88 14 33 0f b6 00 0f b6 d2 03 c2 33 d2 f7 f1 8b 4d f0 8a 04 32 32 04 39 88 07 47 ff 4d 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}