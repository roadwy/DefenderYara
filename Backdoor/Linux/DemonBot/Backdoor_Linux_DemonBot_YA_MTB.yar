
rule Backdoor_Linux_DemonBot_YA_MTB{
	meta:
		description = "Backdoor:Linux/DemonBot.YA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 20 30 6e 20 55 72 20 46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4c 33 33 54 20 48 61 78 45 72 53 } //4 Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS
		$a_00_1 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 20 2b 20 2f 78 35 34 2f 78 } //1 TSource Engine Query + /x54/x
		$a_01_2 = {33 31 6d 56 35 2e 30 } //1 31mV5.0
		$a_01_3 = {33 31 6d 44 65 6d 6f 6e } //1 31mDemon
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}