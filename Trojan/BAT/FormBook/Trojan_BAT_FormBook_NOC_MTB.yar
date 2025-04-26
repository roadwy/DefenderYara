
rule Trojan_BAT_FormBook_NOC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 16 61 04 16 60 ?? ?? 00 00 0a 0a 12 00 ?? ?? 00 00 0a 16 61 } //2
		$a_03_1 = {a2 08 17 58 0c 08 02 ?? ?? 00 00 06 8e 69 32 c6 06 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}