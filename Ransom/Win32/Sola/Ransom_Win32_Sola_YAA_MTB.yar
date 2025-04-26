
rule Ransom_Win32_Sola_YAA_MTB{
	meta:
		description = "Ransom:Win32/Sola.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 fc 0f b6 02 35 aa 00 00 00 8b 4d 08 03 4d fc 88 01 } //1
		$a_01_1 = {73 6f 6c 61 } //1 sola
		$a_01_2 = {2d 2d 66 6f 6f 64 } //1 --food
		$a_01_3 = {4d 65 6f 77 } //1 Meow
		$a_01_4 = {2d 2d 72 65 73 74 } //1 --rest
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}