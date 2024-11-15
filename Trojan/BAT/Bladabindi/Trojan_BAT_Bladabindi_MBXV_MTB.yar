
rule Trojan_BAT_Bladabindi_MBXV_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 00 03 26 00 00 03 41 00 00 11 43 00 75 00 75 00 67 00 6f 00 64 00 6e 00 61 00 00 13 43 00 72 00 72 00 46 00 71 } //2
		$a_01_1 = {73 64 66 73 64 66 73 } //1 sdfsdfs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}