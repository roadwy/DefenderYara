
rule Ransom_Win32_Beast_YAA_MTB{
	meta:
		description = "Ransom:Win32/Beast.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 74 04 0c 55 40 83 f8 0b 72 f5 } //1
		$a_03_1 = {0b c8 8b 45 ec 31 4d ?? 23 45 ?? 8b 4d ?? f7 d1 23 4d e0 33 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}