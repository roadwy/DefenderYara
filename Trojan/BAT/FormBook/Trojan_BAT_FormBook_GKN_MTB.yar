
rule Trojan_BAT_FormBook_GKN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.GKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 28 03 00 00 2b 73 8d 00 00 0a a2 25 17 72 d5 02 00 70 a2 25 18 72 e3 02 00 70 a2 0c d0 6f 00 00 01 28 85 00 00 0a 72 ff 02 00 70 20 00 01 00 00 14 14 18 8d 10 00 00 01 25 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}