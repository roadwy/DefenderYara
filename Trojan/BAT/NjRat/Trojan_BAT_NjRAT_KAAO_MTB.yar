
rule Trojan_BAT_NjRAT_KAAO_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 10 13 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}