
rule Trojan_Win32_Hidcsfile_A{
	meta:
		description = "Trojan:Win32/Hidcsfile.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 77 69 6e 64 69 72 25 5c 4f 66 66 6c 69 6e 65 20 57 65 62 20 50 61 67 65 73 5c 69 63 6f 5c } //01 00  %windir%\Offline Web Pages\ico\
		$a_01_1 = {5c 4f 66 66 6c 69 6e 65 20 57 65 62 20 50 61 67 65 73 5c 77 65 62 5c 77 65 62 2e 65 78 65 20 20 22 22 25 31 22 22 20 25 2a } //01 00  \Offline Web Pages\web\web.exe  ""%1"" %*
		$a_01_2 = {49 65 78 70 6c 6f 72 65 2e 65 78 65 5f 5f 5f 0d 0a 2f 2f 5f 5f 5f 5f 68 74 74 70 3a 2f 2f 77 77 77 2e 74 61 6f 62 61 6f 2e 63 6f 6d 2f } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 36 34 25 36 38 25 32 45 25 36 34 25 36 38 25 33 39 25 33 31 25 33 39 25 32 45 25 36 33 25 36 46 25 36 44 2f 3f 69 64 3d } //01 00  http://%64%68%2E%64%68%39%31%39%2E%63%6F%6D/?id=
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 64 63 73 66 69 6c 65 5c 53 63 72 69 70 74 45 6e 67 69 6e 65 } //00 00  SOFTWARE\Classes\dcsfile\ScriptEngine
	condition:
		any of ($a_*)
 
}