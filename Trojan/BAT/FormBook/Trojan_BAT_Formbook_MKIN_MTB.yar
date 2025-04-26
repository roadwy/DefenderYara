
rule Trojan_BAT_Formbook_MKIN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MKIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 05 00 00 0a 0a 73 06 00 00 0a 0b 06 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 00 00 06 16 6f ?? ?? ?? 0a 0c 16 0d 38 14 00 00 00 08 09 91 13 04 00 07 11 04 6f ?? ?? ?? 0a 00 00 09 17 58 0d 09 08 8e 69 3f e3 ff ff ff 07 6f ?? ?? ?? 0a 00 07 13 05 38 00 00 00 00 11 05 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}