
rule Trojan_Win32_Cobaltstrike_MK_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a1 fc fe 54 00 33 c1 c7 05 90 01 04 90 01 04 01 05 90 1b 00 8b ff a1 90 01 04 8b 0d 90 1b 00 89 08 5f 5d c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Cobaltstrike_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Cobaltstrike.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c5 04 0f af 5f 30 8b 87 90 01 04 8b d3 c1 ea 10 88 14 01 8b d3 ff 47 38 8b 8f 90 01 04 8b 47 3c 81 c1 90 01 04 03 c1 c1 ea 08 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Cobaltstrike_MK_MTB_3{
	meta:
		description = "Trojan:Win32/Cobaltstrike.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 48 02 c1 e1 90 01 01 33 f9 0f b6 48 01 c1 e1 90 01 01 33 f9 0f b6 00 33 c7 69 f8 90 01 04 8b c7 c1 e8 90 01 01 33 c7 69 c8 90 1b 02 5f 5e 8b c1 c1 e8 90 01 01 33 c1 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}