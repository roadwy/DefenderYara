
rule Ransom_Win64_Ryuk_E_MSR{
	meta:
		description = "Ransom:Win64/Ryuk.E!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 61 6b 44 66 4c 64 76 48 75 57 64 50 78 52 45 58 44 52 4f 45 73 37 58 43 6f 4d 41 } //01 00  TakDfLdvHuWdPxREXDROEs7XCoMA
		$a_01_1 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f 41 } //01 00  GetMonitorInfoA
		$a_01_2 = {54 00 65 00 73 00 74 00 47 00 64 00 69 00 70 00 42 00 75 00 74 00 74 00 6f 00 6e 00 2e 00 45 00 58 00 45 00 } //01 00  TestGdipButton.EXE
		$a_01_3 = {69 43 43 50 50 68 6f 74 6f 73 68 6f 70 20 49 43 43 20 70 72 6f 66 69 6c 65 } //00 00  iCCPPhotoshop ICC profile
		$a_01_4 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}