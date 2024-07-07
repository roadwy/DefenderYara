
rule PWS_Win32_OnLineGames_Lowfi{
	meta:
		description = "PWS:Win32/OnLineGames!Lowfi,SIGNATURE_TYPE_PEHSTR,32 00 32 00 05 00 00 "
		
	strings :
		$a_01_0 = {d1 e8 73 05 35 20 83 b8 ed 4a 75 f4 49 75 e7 } //1
		$a_01_1 = {4e 00 6f 00 61 00 68 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 NoahSystem
		$a_01_2 = {4b 00 6e 00 69 00 67 00 68 00 74 00 20 00 4f 00 6e 00 6c 00 69 00 6e 00 65 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Knight Online Client
		$a_01_3 = {57 00 61 00 72 00 66 00 61 00 72 00 65 00 } //1 Warfare
		$a_01_4 = {4b 00 6e 00 69 00 67 00 68 00 74 00 4f 00 6e 00 6c 00 69 00 6e 00 65 00 2e 00 65 00 78 00 65 00 } //1 KnightOnline.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=50
 
}