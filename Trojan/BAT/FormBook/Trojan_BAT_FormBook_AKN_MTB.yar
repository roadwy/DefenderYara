
rule Trojan_BAT_FormBook_AKN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 11 04 6f ?? 00 00 0a 13 09 19 8d ?? 00 00 01 25 16 12 09 28 ?? 00 00 0a 6c 07 16 9a 16 99 5a a1 25 17 12 09 28 ?? 00 00 0a 6c 07 17 9a 17 99 5a a1 25 18 12 09 28 ?? 00 00 0a 6c 07 18 9a 18 99 5a a1 } //2
		$a_01_1 = {43 00 61 00 6c 00 63 00 75 00 6c 00 61 00 64 00 6f 00 72 00 61 00 4d 00 65 00 64 00 69 00 61 00 41 00 6c 00 75 00 6e 00 6f 00 } //1 CalculadoraMediaAluno
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}