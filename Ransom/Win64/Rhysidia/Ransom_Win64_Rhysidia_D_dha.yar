
rule Ransom_Win64_Rhysidia_D_dha{
	meta:
		description = "Ransom:Win64/Rhysidia.D!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 68 79 73 69 64 61 } //01 00  Rhysida
		$a_01_1 = {43 72 69 74 69 63 61 6c 42 72 65 61 63 68 44 65 74 65 63 74 65 64 2e 70 64 66 } //01 00  CriticalBreachDetected.pdf
		$a_01_2 = {72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 63 74 69 76 65 44 65 73 6b 74 6f 70 22 20 2f 76 20 4e 6f 43 68 61 6e 67 69 6e 67 57 61 6c 6c 50 61 70 65 72 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 31 20 2f 66 } //00 00  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v NoChangingWallPaper /t REG_SZ /d 1 /f
	condition:
		any of ($a_*)
 
}