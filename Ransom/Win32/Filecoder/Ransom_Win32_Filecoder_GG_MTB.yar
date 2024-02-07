
rule Ransom_Win32_Filecoder_GG_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 68 2e 76 62 73 } //01 00  Microsoft\Windows\Start Menu\Programs\Startup\h.vbs
		$a_81_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  CreateObject("WScript.Shell")
		$a_81_2 = {65 69 63 61 72 2e 63 6f 6d } //01 00  eicar.com
		$a_81_3 = {75 73 65 72 70 72 6f 66 69 6c 65 } //01 00  userprofile
		$a_81_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 49 4d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  taskkill /f /IM explorer.exe
		$a_81_5 = {21 50 25 40 41 50 5b 34 5c 50 5a 58 35 34 28 50 } //00 00  !P%@AP[4\PZX54(P
	condition:
		any of ($a_*)
 
}