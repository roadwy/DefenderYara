
rule Trojan_BAT_Darkcomet_AMH_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.AMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 17 02 28 ?? ?? ?? 0a b5 13 04 0b 2b 26 06 09 02 07 17 28 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}