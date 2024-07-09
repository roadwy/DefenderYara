
rule TrojanDownloader_Win32_Garveep_B{
	meta:
		description = "TrojanDownloader:Win32/Garveep.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 72 72 6f 72 20 74 6f 20 67 65 74 20 48 44 44 20 66 69 72 6d 77 61 72 65 20 73 65 72 69 61 6c } //3 error to get HDD firmware serial
		$a_01_1 = {2d 7d 7a 69 6c 6c 61 5d 46 5c 42 40 48 71 7d 6d 62 61 66 69 70 6c 65 5b 40 2d 33 29 25 40 57 5c 42 5b 40 37 69 7c 64 7d 77 73 40 3c 26 40 47 5c 43 49 } //3 -}zilla]F\B@Hq}mbafiple[@-3)%@W\B[@7i|d}ws@<&@G\CI
		$a_01_2 = {64 7d 77 7c 6c 7d 61 64 65 72 73 65 66 66 69 7c 75 } //2 d}w|l}aderseffi|u
		$a_03_3 = {3d 97 01 00 00 0f 84 ?? ?? ?? ?? 68 00 04 00 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2) >=7
 
}