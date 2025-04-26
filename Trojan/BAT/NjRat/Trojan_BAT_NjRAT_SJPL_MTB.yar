
rule Trojan_BAT_NjRAT_SJPL_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.SJPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 10 59 0d 06 09 03 08 18 6f 31 00 00 0a 1f 10 28 32 00 00 0a 07 09 07 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f 30 00 00 0a 32 b6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}