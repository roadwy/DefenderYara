
rule Trojan_Win32_Mades_A{
	meta:
		description = "Trojan:Win32/Mades.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_01_1 = {5c 6d 73 73 65 63 63 2e 65 78 65 } //01 00  \mssecc.exe
		$a_01_2 = {25 73 25 30 38 78 2e 65 78 65 } //01 00  %s%08x.exe
		$a_01_3 = {25 73 20 2f 63 20 64 65 6c 20 25 73 20 3e 3e 4e 55 4c } //01 00  %s /c del %s >>NUL
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 61 6c 77 61 72 65 64 65 73 74 72 75 63 74 6f 72 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 61 69 64 3d } //01 00  http://www.malwaredestructor.com/download.php?aid=
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}