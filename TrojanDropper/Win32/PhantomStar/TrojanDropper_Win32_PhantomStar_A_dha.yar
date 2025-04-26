
rule TrojanDropper_Win32_PhantomStar_A_dha{
	meta:
		description = "TrojanDropper:Win32/PhantomStar.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b f1 57 b9 81 00 00 00 33 c0 8d bd 9e fd ff ff 66 c7 85 9c fd ff ff 00 00 f3 ab } //10
		$a_01_1 = {25 73 5c 45 6e 54 61 73 6b 4c 6f 61 64 65 72 2e 65 78 65 } //1 %s\EnTaskLoader.exe
		$a_01_2 = {2f 00 74 00 61 00 73 00 6b 00 2d 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 } //1 /task-restart
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}