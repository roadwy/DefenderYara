
rule PWS_Win32_OnLineGames_CRT_sys{
	meta:
		description = "PWS:Win32/OnLineGames.CRT!sys,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 61 6d 65 48 61 63 6b 5c 44 72 69 76 65 72 5c 62 69 6e 5c 69 33 38 36 5c 6d 73 73 6f 63 6b 2e 70 64 62 } //2 GameHack\Driver\bin\i386\mssock.pdb
		$a_01_1 = {5c 00 3f 00 3f 00 5c 00 6d 00 61 00 73 00 70 00 69 00 } //2 \??\maspi
		$a_01_2 = {49 6f 44 65 6c 65 74 65 44 65 76 69 63 65 } //2 IoDeleteDevice
		$a_01_3 = {8b c0 8b c0 8b c0 90 90 90 90 } //2
		$a_01_4 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 43 00 6c 00 61 00 73 00 73 00 30 00 } //1 \Device\KeyboardClass0
		$a_01_5 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 6d 00 61 00 73 00 70 00 69 00 } //1 \Device\maspi
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}