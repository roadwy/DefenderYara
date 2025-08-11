
rule Trojan_BAT_Heracles_EHHK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EHHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 40 07 09 0f 02 ?? ?? ?? ?? ?? 05 0e 04 09 6b 06 5a 58 6c ?? ?? ?? ?? ?? 6b 5a 58 0f 02 ?? ?? ?? ?? ?? 05 0e 04 09 6b 06 5a 58 6c ?? ?? ?? ?? ?? 6b 5a 58 73 2b 00 00 0a a4 15 00 00 01 09 17 58 0d 09 19 32 bc } //2
		$a_03_1 = {1f 19 18 11 04 5a 59 13 05 11 05 20 ff 00 00 00 16 16 ?? ?? ?? ?? ?? 73 32 00 00 0a 13 06 05 11 04 18 5a 6b 58 13 07 03 11 06 0f 02 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}