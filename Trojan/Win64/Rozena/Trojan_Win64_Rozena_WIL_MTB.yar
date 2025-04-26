
rule Trojan_Win64_Rozena_WIL_MTB{
	meta:
		description = "Trojan:Win64/Rozena.WIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 48 8b 1d 7a 98 04 00 89 35 d6 73 04 00 33 95 7b ff ff ff 8a 75 9f 2b 15 ae 84 04 00 89 5d 85 8b 7d a7 81 ef 02 23 00 00 48 8b 5d d4 48 c7 c0 ?? ?? ?? ?? 8b 55 de ba c5 4e 00 00 4c 3b 15 92 8f 04 00 70 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}