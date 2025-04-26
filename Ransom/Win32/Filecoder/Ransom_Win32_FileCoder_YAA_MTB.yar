
rule Ransom_Win32_FileCoder_YAA_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 0e 33 c8 89 4e 20 47 83 c6 04 3b 7d f8 } //1
		$a_03_1 = {33 c2 41 89 4d fc 83 fb 04 75 ?? 8b c8 c1 e9 10 81 e1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}