
rule Backdoor_Linux_DemonBot_Ab_MTB{
	meta:
		description = "Backdoor:Linux/DemonBot.Ab!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 54 41 52 54 49 4e 47 20 54 45 4c 4e 45 54 20 53 43 41 4e 4e 45 52 } //1 STARTING TELNET SCANNER
		$a_00_1 = {53 54 41 52 54 49 4e 47 20 31 30 35 20 53 43 41 4e 4e 45 52 } //1 STARTING 105 SCANNER
		$a_02_2 = {63 64 20 2f 74 6d 70 3b 62 75 73 79 62 6f 78 20 77 67 65 74 20 ?? ?? ?? ?? 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f 69 6e 66 65 63 74 20 2d 4f 20 2d 20 3e 20 [0-10] 3b 20 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 [0-10] 3b 20 73 68 20 2f 74 6d 70 2f } //2
		$a_00_3 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 20 30 6e 20 55 72 20 46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4c 33 33 54 20 48 61 78 } //2 Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T Hax
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2) >=5
 
}