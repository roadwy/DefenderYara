
rule Ransom_MacOS_EvilQuest_A_MTB{
	meta:
		description = "Ransom:MacOS/EvilQuest.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 49 5f 54 45 4d 50 5f 57 41 53 5f 55 50 44 41 54 45 44 } //1 EI_TEMP_WAS_UPDATED
		$a_01_1 = {45 49 5f 55 4c 44 5f 44 49 52 45 43 54 4f 52 59 } //1 EI_ULD_DIRECTORY
		$a_01_2 = {d3 db e2 68 27 2e 02 51 42 44 d9 2c 25 3a 32 f9 f4 b5 9e dc 21 80 14 50 ef 13 e0 06 40 f3 11 83 2f d9 bb fa 43 47 2c 17 0c 40 42 c1 82 62 1c 19 e8 97 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}