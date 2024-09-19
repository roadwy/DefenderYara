
rule Ransom_Win64_Sola_YAC_MTB{
	meta:
		description = "Ransom:Win64/Sola.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 66 6f 6f 64 } //1 --food
		$a_01_1 = {2d 2d 72 65 73 74 } //1 --rest
		$a_01_2 = {6e 65 74 20 73 74 6f 70 20 77 75 61 75 73 65 72 76 20 3e 20 4e 55 4c } //1 net stop wuauserv > NUL
		$a_01_3 = {2e 73 6f 6c 61 } //1 .sola
		$a_01_4 = {25 73 5c 52 45 41 44 4d 45 2e 74 78 74 } //1 %s\README.txt
		$a_01_5 = {4d 65 6f 77 2e } //1 Meow.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}