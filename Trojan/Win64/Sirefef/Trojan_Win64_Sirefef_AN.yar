
rule Trojan_Win64_Sirefef_AN{
	meta:
		description = "Trojan:Win64/Sirefef.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {38 30 30 30 30 30 30 31 2e 40 } //1 80000001.@
		$a_03_1 = {ba 14 00 00 00 33 c9 ff 15 ?? ?? ?? ?? b9 08 00 00 00 48 8b d8 48 85 c0 74 0f 83 60 08 00 c7 00 01 00 00 00 89 48 04 eb 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}