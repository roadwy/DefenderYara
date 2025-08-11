
rule Trojan_Win64_Stealer_NL_MTB{
	meta:
		description = "Trojan:Win64/Stealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 05 52 63 28 00 45 31 c9 48 83 c0 18 0f 1f 00 4c 8b 00 4c 39 c3 72 13 48 8b 50 08 8b 52 08 49 01 d0 4c 39 c3 0f 82 88 00 00 00 41 83 c1 01 48 83 c0 28 41 39 f1 75 d8 } //2
		$a_01_1 = {48 89 c7 48 85 c0 0f 84 e6 00 00 00 48 8b 05 05 63 28 00 48 8d 1c b6 48 c1 e3 03 48 01 d8 48 89 78 20 c7 00 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}