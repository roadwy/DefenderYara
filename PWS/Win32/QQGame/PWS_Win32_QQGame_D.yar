
rule PWS_Win32_QQGame_D{
	meta:
		description = "PWS:Win32/QQGame.D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d8 6a f4 53 e8 ?? ?? ff ff 3d 88 42 00 00 75 26 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 56 e8 } //5
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 } //1
		$a_01_2 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}