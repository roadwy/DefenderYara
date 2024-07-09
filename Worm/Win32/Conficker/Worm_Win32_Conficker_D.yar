
rule Worm_Win32_Conficker_D{
	meta:
		description = "Worm:Win32/Conficker.D,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {59 33 d2 6a 29 59 f7 f1 83 c2 0a 69 d2 e8 03 00 00 89 95 ?? ?? ff ff 3b d6 76 09 2b d6 52 ff 15 } //10
		$a_00_1 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6b 00 } //1 %SystemRoot%\system32\svchost.exe -k
		$a_00_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 22 00 2c 00 25 00 53 00 } //1 rundll32.exe "%s",%S
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}