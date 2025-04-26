
rule Trojan_Win64_QuasarRAT_PAEY_MTB{
	meta:
		description = "Trojan:Win64/QuasarRAT.PAEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 52 65 76 65 72 73 65 54 65 73 74 5c 41 6e 74 69 52 65 76 65 72 73 65 } //1 AntiReverseTest\AntiReverse
		$a_01_1 = {73 74 61 72 74 20 2f 62 20 50 6f 77 65 72 53 68 65 6c 6c 2e 65 78 65 20 2f 63 20 24 70 72 6f 63 65 73 73 20 3d 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 } //1 start /b PowerShell.exe /c $process = Start-Process -FilePath
		$a_01_2 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 50 61 73 73 54 68 72 75 } //1 -WindowStyle Hidden -PassThru
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 57 00 6f 00 77 00 36 00 34 00 33 00 32 00 4e 00 6f 00 64 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 56 00 69 00 73 00 75 00 61 00 6c 00 53 00 74 00 75 00 64 00 69 00 6f 00 5c 00 31 00 34 00 2e 00 30 00 5c 00 53 00 65 00 74 00 75 00 70 00 5c 00 56 00 43 00 } //1 SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0\Setup\VC
		$a_01_4 = {74 65 6d 70 74 69 6e 67 20 74 6f 20 73 74 61 72 74 20 73 73 76 63 68 6f 73 74 2e 65 78 65 } //1 tempting to start ssvchost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}