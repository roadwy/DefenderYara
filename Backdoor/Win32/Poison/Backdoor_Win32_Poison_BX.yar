
rule Backdoor_Win32_Poison_BX{
	meta:
		description = "Backdoor:Win32/Poison.BX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {39 4d 14 75 15 39 4d 0c 7e 25 8b 45 08 03 c1 80 30 32 41 3b 4d 0c 7c f2 } //1
		$a_01_1 = {85 c0 59 75 0a 8a 06 3c 2e 74 04 3c 5f 75 05 8a 06 88 07 47 46 38 1e 75 ce } //1
		$a_01_2 = {83 c4 14 c6 40 fd 6c c6 40 fe 6e c6 40 ff 6b 8d 85 ec fc ff ff } //1
		$a_01_3 = {63 6d 64 20 2f 63 20 65 72 61 73 65 20 2f 46 20 } //1 cmd /c erase /F 
		$a_01_4 = {00 73 76 63 68 6f 73 74 20 2e 65 78 65 00 } //1 猀捶潨瑳⸠硥e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}