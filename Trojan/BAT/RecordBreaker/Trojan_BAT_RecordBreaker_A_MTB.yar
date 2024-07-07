
rule Trojan_BAT_RecordBreaker_A_MTB{
	meta:
		description = "Trojan:BAT/RecordBreaker.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 09 04 59 d1 6f 90 01 01 00 00 0a 26 90 00 } //2
		$a_01_1 = {08 17 58 0c } //2 ᜈౘ
		$a_01_2 = {08 07 8e 69 } //2
		$a_03_3 = {20 e8 03 00 00 28 90 01 01 00 00 0a 06 17 58 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2) >=8
 
}