
rule Backdoor_Win32_Tapazom_D{
	meta:
		description = "Backdoor:Win32/Tapazom.D,SIGNATURE_TYPE_PEHSTR_EXT,40 01 ffffffdc 00 06 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 03 00 00 00 8d 75 f4 33 db 8d 45 ec 8b cb c1 e1 03 ba ff 00 00 00 d3 e2 23 16 8b cb c1 e1 03 d3 ea e8 } //100
		$a_01_1 = {83 7d e8 ff 75 04 b3 01 eb 60 80 7d f7 0e 74 5a 80 7d f7 0a 74 22 80 7d f7 0d 74 1c 8d 85 d4 f8 ff ff 8a 55 f7 e8 } //100
		$a_01_2 = {6d 7a 6f 2e 68 6f 70 74 6f 2e 6f 72 67 3a 31 34 33 31 } //50 mzo.hopto.org:1431
		$a_01_3 = {2d 4d 75 6c 74 69 63 6f 72 65 2e 65 78 65 } //50 -Multicore.exe
		$a_01_4 = {43 61 72 76 69 65 72 } //20 Carvier
		$a_01_5 = {64 6f 74 33 64 6c 78 65 2e 64 6c 6c } //10 dot3dlxe.dll
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*50+(#a_01_3  & 1)*50+(#a_01_4  & 1)*20+(#a_01_5  & 1)*10) >=220
 
}