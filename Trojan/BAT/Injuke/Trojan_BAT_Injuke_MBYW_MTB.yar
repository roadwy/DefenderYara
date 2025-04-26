
rule Trojan_BAT_Injuke_MBYW_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MBYW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 61 00 64 00 00 27 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 6b 00 69 00 73 00 6f 00 6e 00 69 00 39 00 63 00 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}