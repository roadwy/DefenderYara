
rule Trojan_BAT_Bladabindi_RDA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 18 63 17 5f d2 9c 07 17 58 0b 07 02 8e 69 } //2
		$a_01_1 = {42 61 73 65 64 41 6e 74 69 56 54 2e 65 78 65 } //1 BasedAntiVT.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}