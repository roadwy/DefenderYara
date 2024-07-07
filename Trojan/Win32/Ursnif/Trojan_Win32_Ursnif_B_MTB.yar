
rule Trojan_Win32_Ursnif_B_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 cb 2b c1 01 05 90 01 04 a1 90 01 04 8b 4c 24 90 01 01 05 90 01 04 a3 90 01 04 89 01 0f b7 c3 83 c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_B_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e9 5f 8b 1d 90 01 04 8b ee 6b ed 45 03 ef 39 1d 90 01 04 76 06 01 35 90 01 04 8b 54 24 10 05 20 af 8e 01 a3 90 01 04 89 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_B_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6b c0 4d 8b 90 01 05 2b 90 01 01 8b 90 01 01 f4 2b 90 01 01 89 90 01 01 f4 a1 90 00 } //1
		$a_02_1 = {70 66 37 01 89 90 01 05 8b 90 01 05 03 90 01 01 f0 a1 90 01 04 89 90 01 01 42 e9 ff ff 90 01 06 6b 90 01 01 4d 8b 90 01 01 f4 2b 90 01 01 8b 90 01 01 f4 2b 90 01 01 89 90 01 01 f4 8b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}