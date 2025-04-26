
rule Trojan_Win32_RisePro_KAB_MTB{
	meta:
		description = "Trojan:Win32/RisePro.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 65 6b 6d 74 6e 64 66 61 } //1 dekmtndfa
		$a_01_1 = {6d 62 61 6d 6e 67 6a 6a 62 } //1 mbamngjjb
		$a_01_2 = {68 71 6e 68 61 6b 6a 61 63 } //1 hqnhakjac
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}