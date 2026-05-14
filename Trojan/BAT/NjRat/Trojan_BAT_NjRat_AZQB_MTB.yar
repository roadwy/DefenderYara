
rule Trojan_BAT_NjRat_AZQB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AZQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {17 0c 2b 32 0f 01 08 17 03 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 20 00 ?? 00 00 da 04 6f ?? 00 00 0a d6 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 00 08 17 d6 0c 08 07 31 ca } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}