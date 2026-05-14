
rule Trojan_Win32_Dllinjector_O_AMTB{
	meta:
		description = "Trojan:Win32/Dllinjector.O!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_80_0 = {67 61 6d 65 73 65 6e 73 65 2e 6c 69 76 65 } //gamesense.live  2
		$a_80_1 = {50 6c 65 61 73 65 2c 20 6c 61 75 6e 63 68 20 43 53 3a 47 4f 20 79 6f 75 72 73 65 6c 66 2e } //Please, launch CS:GO yourself.  2
		$a_80_2 = {56 41 43 20 62 79 70 61 73 73 20 69 6e 6a 65 63 74 69 6f 6e } //VAC bypass injection  2
		$a_80_3 = {5b 50 52 4f 43 45 53 53 20 49 4e 4a 45 43 54 49 4f 4e 5d } //[PROCESS INJECTION]  2
		$a_80_4 = {59 4f 55 20 43 41 4e 20 47 45 54 20 56 41 43 20 42 41 4e } //YOU CAN GET VAC BAN  2
		$a_80_5 = {44 4c 4c 20 70 61 74 68 20 77 72 69 74 74 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //DLL path written successfully.  2
		$a_80_6 = {73 6b 65 65 74 2e 64 6c 6c } //skeet.dll  2
		$a_80_7 = {77 61 69 74 69 6e 67 20 66 6f 72 20 63 73 67 6f 2e 65 78 65 } //waiting for csgo.exe  2
		$a_80_8 = {5c 69 6e 6a 65 63 74 6f 72 5c 73 6b 65 65 74 2d 69 6e 6a 65 63 74 6f 72 2e 70 64 62 } //\injector\skeet-injector.pdb  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2) >=18
 
}