
rule TrojanDownloader_Win32_Obitel_A{
	meta:
		description = "TrojanDownloader:Win32/Obitel.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {66 69 78 61 73 65 72 76 65 72 2e 72 75 } //1 fixaserver.ru
		$a_00_1 = {6c 64 72 32 2f 67 61 74 65 2e 70 68 70 } //1 ldr2/gate.php
		$a_00_2 = {68 61 73 68 3d } //1 hash=
		$a_00_3 = {51 75 65 75 65 55 73 65 72 41 50 43 } //1 QueueUserAPC
		$a_00_4 = {75 73 65 72 69 6e 69 2e 65 78 65 } //1 userini.exe
		$a_03_5 = {53 55 56 57 33 ed 55 55 55 68 ?? ?? ?? ?? 55 55 ff 15 ?? ?? 40 00 8b ?? ?? ?? ?? ?? 55 8b f0 56 68 ?? ?? ?? ?? ff d7 8b ?? ?? ?? ?? ?? 55 68 ec 00 00 00 ff d3 55 56 68 ?? ?? ?? ?? ff d7 56 ff 15 ?? ?? 40 00 6a 01 6a ff ff d3 5f 5e 5d 33 c0 5b c2 10 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}