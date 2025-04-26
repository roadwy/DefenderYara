
rule Trojan_BAT_LummaC_ALA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 bc fa 4a 03 d3 c1 57 51 3f 38 49 f6 fb 5a ca 9a a5 6b 15 90 2e 97 ce c1 51 63 a9 cc 12 e2 0d 6b 88 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}