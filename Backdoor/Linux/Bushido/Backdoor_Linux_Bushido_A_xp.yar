
rule Backdoor_Linux_Bushido_A_xp{
	meta:
		description = "Backdoor:Linux/Bushido.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 69 47 47 65 52 64 30 6e 6b 73 31 33 33 37 } //1 NiGGeRd0nks1337
		$a_01_1 = {53 4f 31 39 30 49 6a 31 58 } //1 SO190Ij1X
		$a_01_2 = {31 33 33 37 53 6f 72 61 4c 4f 41 44 45 52 } //1 1337SoraLOADER
		$a_00_3 = {73 63 61 6e 78 38 36 } //1 scanx86
		$a_03_4 = {47 45 54 20 2f 73 68 65 6c 6c 3f 63 64 2b 2f 74 6d 70 3b 2b 77 67 65 74 2b 68 74 74 70 3a 2f 5c 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f [0-10] 2f [0-10] 2e 61 72 6d 3b 2b 63 68 6d 6f 64 2b 37 37 37 2b [0-10] 2e 61 72 6d 3b 2b 2e 2f [0-10] 2e 61 72 6d 20 4a 61 77 73 2e 53 65 6c 66 72 65 70 3b 72 6d 2b 2d 72 66 2b [0-10] 2e 61 72 6d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*2) >=3
 
}