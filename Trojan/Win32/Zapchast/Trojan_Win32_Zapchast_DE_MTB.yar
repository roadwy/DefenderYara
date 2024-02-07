
rule Trojan_Win32_Zapchast_DE_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 08 00 00 03 00 "
		
	strings :
		$a_81_0 = {2f 6d 69 78 6f 6e 65 } //03 00  /mixone
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 69 6e 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 6f 75 74 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 43 6f 6d 6d 61 6e 64 } //03 00  powershell -inputformat none -outputformat none -NonInteractive -Command
		$a_81_2 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //03 00  DisableRealtimeMonitoring
		$a_81_3 = {45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //03 00  ExclusionPath
		$a_81_4 = {5a 4e 36 63 75 72 6c 70 70 31 30 4f 70 74 69 6f 6e 42 61 73 65 43 32 45 31 30 43 55 52 4c 6f 70 74 69 6f 6e } //03 00  ZN6curlpp10OptionBaseC2E10CURLoption
		$a_81_5 = {63 75 72 6c 5f 65 61 73 79 5f 73 65 74 6f 70 74 } //03 00  curl_easy_setopt
		$a_81_6 = {72 65 70 6f 72 74 5f 65 72 72 6f 72 2e 70 68 70 3f 6b 65 79 3d 31 32 35 34 37 38 38 32 34 35 31 35 41 44 4e 78 75 32 63 63 62 77 65 } //03 00  report_error.php?key=125478824515ADNxu2ccbwe
		$a_81_7 = {4e 6f 2d 45 78 65 73 2d 46 6f 75 6e 64 2d 54 6f 2d 52 75 6e } //00 00  No-Exes-Found-To-Run
	condition:
		any of ($a_*)
 
}