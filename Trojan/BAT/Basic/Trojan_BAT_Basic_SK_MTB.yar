
rule Trojan_BAT_Basic_SK_MTB{
	meta:
		description = "Trojan:BAT/Basic.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0b 17 58 13 0b 06 11 0a 11 0b 58 91 06 07 11 0b 58 91 33 05 11 0b 09 32 e6 } //2
		$a_81_1 = {70 69 72 69 2e 65 78 65 } //2 piri.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}