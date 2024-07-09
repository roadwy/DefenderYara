
rule TrojanDropper_Win32_Evotob_A{
	meta:
		description = "TrojanDropper:Win32/Evotob.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 00 10 00 00 74 ?? 3d 00 20 00 00 72 ?? 3d 00 30 00 00 73 ?? 43 eb ?? 3d 00 30 00 00 72 ?? 6a 02 eb ?? 3d 00 40 00 00 72 ?? 6a 03 } //1
		$a_01_1 = {ff 65 40 40 ff 65 40 41 ff 65 40 42 ff 65 40 43 ff 65 40 46 ff 65 40 47 ff 65 40 } //1
		$a_03_2 = {0f b7 46 1e 8d 44 30 20 50 68 04 01 00 00 ff 75 08 e8 ?? ?? ?? ?? 8b 46 0c 83 c4 0c 89 45 f4 } //1
		$a_01_3 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //1 joeboxcontrol.exe
		$a_00_4 = {52 75 6e 59 6f 75 72 4d 61 6c 77 61 72 65 48 65 72 65 } //1 RunYourMalwareHere
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=2
 
}