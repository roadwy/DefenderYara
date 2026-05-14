
rule Trojan_BAT_Shellcode_ARR_MTB{
	meta:
		description = "Trojan:BAT/Shellcode.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 06 8e 69 20 ?? ?? ?? 00 1f 40 6f ?? ?? ?? ?? 0b 06 16 07 06 8e 69 28 } //11
		$a_01_1 = {16 16 07 09 16 12 04 6f } //9 ᘖइሖ漄
	condition:
		((#a_03_0  & 1)*11+(#a_01_1  & 1)*9) >=20
 
}