
rule Trojan_BAT_LummaC_CCID_MTB{
	meta:
		description = "Trojan:BAT/LummaC.CCID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 03 08 1f 09 5d 9a 28 ?? 00 00 0a 02 08 91 28 ?? 00 00 06 b4 9c 08 17 d6 0c 08 07 31 e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}