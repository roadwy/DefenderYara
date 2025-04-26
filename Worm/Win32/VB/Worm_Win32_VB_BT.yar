
rule Worm_Win32_VB_BT{
	meta:
		description = "Worm:Win32/VB.BT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 75 74 6f 74 78 74 } //1 autotxt
		$a_00_1 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_00_2 = {69 00 65 00 70 00 72 00 6f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ieproloader.exe
		$a_00_3 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 6c 6f 76 65 62 7a 69 68 75 69 2e 65 78 65 } //1 shell\open\Command=lovebzihui.exe
		$a_03_4 = {8b 55 d4 52 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 f7 d8 1b c0 40 f7 d8 66 89 85 70 ff ff ff c7 85 68 ff ff ff 0b 00 00 00 8d 45 ac 50 8d 8d 78 ff ff ff 51 8d 55 9c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}