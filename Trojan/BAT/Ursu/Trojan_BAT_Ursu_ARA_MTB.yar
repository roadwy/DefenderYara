
rule Trojan_BAT_Ursu_ARA_MTB{
	meta:
		description = "Trojan:BAT/Ursu.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 02 08 91 08 58 06 08 91 58 d2 9c 08 17 58 0c 08 07 8e 69 32 e9 07 28 0b 01 00 0a } //2
		$a_01_1 = {46 75 63 6b 41 56 } //2 FuckAV
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}