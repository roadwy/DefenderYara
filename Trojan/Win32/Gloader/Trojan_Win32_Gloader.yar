
rule Trojan_Win32_Gloader{
	meta:
		description = "Trojan:Win32/Gloader,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 69 6e 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 6f 75 74 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //1 powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath
		$a_01_1 = {72 65 70 6f 72 74 5f 65 72 72 6f 72 2e 70 68 70 3f 6b 65 79 3d } //1 report_error.php?key=
		$a_01_2 = {36 32 31 32 33 34 34 39 31 64 35 38 37 2e 63 6f 6d } //1 621234491d587.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}