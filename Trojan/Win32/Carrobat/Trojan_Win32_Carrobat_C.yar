
rule Trojan_Win32_Carrobat_C{
	meta:
		description = "Trojan:Win32/Carrobat.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 64 65 6c 20 2f 66 20 2f 71 } //1 /c del /f /q
		$a_01_1 = {72 65 6e 20 31 2e 74 78 74 20 31 2e 62 61 74 } //1 ren 1.txt 1.bat
		$a_01_2 = {26 26 20 31 2e 62 61 74 20 26 26 20 65 78 69 74 } //1 && 1.bat && exit
		$a_01_3 = {43 3a 20 26 26 20 63 64 20 25 54 45 4d 50 25 } //1 C: && cd %TEMP%
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}