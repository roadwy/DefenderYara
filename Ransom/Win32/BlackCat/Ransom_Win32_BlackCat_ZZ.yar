
rule Ransom_Win32_BlackCat_ZZ{
	meta:
		description = "Ransom:Win32/BlackCat.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {8b 45 08 66 0f 6f 02 66 0f 38 00 00 66 0f 7f 01 } //10
		$a_03_2 = {68 c0 1f 00 00 68 ?? ?? ?? ?? [0-07] 50 e8 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10) >=21
 
}