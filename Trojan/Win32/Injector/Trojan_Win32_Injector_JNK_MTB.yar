
rule Trojan_Win32_Injector_JNK_MTB{
	meta:
		description = "Trojan:Win32/Injector.JNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 00 08 04 40 0b 98 0d bf 04 c2 01 11 0a 00 ff 03 26 00 00 00 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Injector_JNK_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.JNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_81_0 = {66 8b 10 66 3b 11 0f 85 1b 03 00 00 66 3b d3 74 19 66 8b 50 02 66 3b 51 02 0f 85 08 03 00 00 83 c0 04 83 c1 04 66 3b d3 75 d6 } //1
	condition:
		((#a_81_0  & 1)*1) >=1
 
}