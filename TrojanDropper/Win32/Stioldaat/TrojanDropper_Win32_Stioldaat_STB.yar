
rule TrojanDropper_Win32_Stioldaat_STB{
	meta:
		description = "TrojanDropper:Win32/Stioldaat.STB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {00 4c 69 62 31 2e 64 6c 6c 00 } //1 䰀扩⸱汤l
		$a_00_1 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 [0-0a] 44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 [0-06] 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c } //1
		$a_00_2 = {5c 72 65 6c 65 61 2e 70 64 62 } //1 \relea.pdb
		$a_01_3 = {81 f7 6e 74 65 6c 8b 45 e8 35 69 6e 65 49 89 45 f8 8b 45 e0 35 47 65 6e 75 89 45 fc 33 c0 40 } //2
		$a_01_4 = {6a 00 68 00 ca 9a 3b 52 50 8b f1 e8 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=7
 
}