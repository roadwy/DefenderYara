
rule Trojan_BAT_FormBook_AIY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 02 50 8e 69 17 59 0b ?? ?? ?? ?? ?? 02 50 06 91 0c 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}