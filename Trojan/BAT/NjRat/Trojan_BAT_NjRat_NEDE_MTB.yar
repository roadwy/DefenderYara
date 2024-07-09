
rule Trojan_BAT_NjRat_NEDE_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 1b 11 1b 3a ae fe ff ff 28 ?? 00 00 0a 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 07 14 } //10
		$a_01_1 = {68 61 6a 7a 61 2e 70 64 62 } //5 hajza.pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}