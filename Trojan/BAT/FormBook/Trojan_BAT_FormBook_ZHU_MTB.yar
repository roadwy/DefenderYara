
rule Trojan_BAT_FormBook_ZHU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ZHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 61 d2 9c 25 17 0f 00 28 ?? ?? ?? ?? 16 60 d2 9c 25 18 0f 00 28 ?? ?? ?? ?? 20 ff 00 00 00 5f d2 9c } //6
		$a_03_1 = {13 04 04 19 8d ?? 00 00 01 25 16 08 9c 25 17 09 9c 25 18 11 04 9c } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}