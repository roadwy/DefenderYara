
rule TrojanDownloader_Win32_BabylonRAT_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/BabylonRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 6f 20 40 63 75 72 6c 20 2d 6f } //2 do @curl -o
		$a_01_1 = {66 6f 72 20 2f 66 20 22 64 65 6c 69 6d 73 3d 22 20 25 69 20 69 6e 20 28 27 63 75 72 6c 20 2d 73 } //2 for /f "delims=" %i in ('curl -s
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 69 6e 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 6f 75 74 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //4 powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*4) >=8
 
}