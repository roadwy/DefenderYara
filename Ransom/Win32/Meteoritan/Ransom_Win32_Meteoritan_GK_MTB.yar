
rule Ransom_Win32_Meteoritan_GK_MTB{
	meta:
		description = "Ransom:Win32/Meteoritan.GK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 68 65 72 65 5f 61 72 65 5f 79 6f 75 72 5f 66 69 6c 65 73 2e 74 78 74 } //1 where_are_your_files.txt
		$a_01_1 = {6d 65 74 65 6f 72 69 74 61 6e 36 35 37 30 40 79 61 6e 64 65 78 2e 72 75 } //1 meteoritan6570@yandex.ru
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}