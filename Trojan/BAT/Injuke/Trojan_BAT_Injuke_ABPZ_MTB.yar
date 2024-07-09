
rule Trojan_BAT_Injuke_ABPZ_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ABPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 9a 13 09 11 04 11 09 1f 10 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 00 11 05 17 d6 13 05 00 11 05 09 8e 69 fe 04 13 0a 11 0a 2d d4 } //4
		$a_01_1 = {50 00 69 00 72 00 61 00 74 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Pirates.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}