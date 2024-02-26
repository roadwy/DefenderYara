
rule Ransom_Win32_FileCoder_YAA_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0e 33 c8 89 4e 20 47 83 c6 04 3b 7d f8 } //01 00 
		$a_03_1 = {33 c2 41 89 4d fc 83 fb 04 75 90 01 01 8b c8 c1 e9 10 81 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}