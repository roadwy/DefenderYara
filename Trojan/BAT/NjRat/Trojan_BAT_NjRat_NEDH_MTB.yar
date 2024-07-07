
rule Trojan_BAT_NjRat_NEDH_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a cb ff ff ff 26 20 01 00 00 00 38 c0 ff ff ff 11 01 2a 11 01 11 02 18 5b 02 11 02 18 6f 09 00 00 0a 1f 10 28 0a 00 00 0a 9c 38 4d 00 00 00 16 13 02 38 ab ff ff ff 02 6f 0b 00 00 0a 13 03 38 0e 00 00 00 11 02 11 03 } //10
		$a_01_1 = {3c 41 75 74 68 50 61 73 73 20 53 65 74 75 70 } //5 <AuthPass Setup
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}