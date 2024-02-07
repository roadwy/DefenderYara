
rule Ransom_MSIL_Filecoder_EF_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {4c 6f 63 6b 65 72 2e 65 78 65 } //01 00  Locker.exe
		$a_81_1 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_81_2 = {45 6d 65 72 67 65 6e 63 79 20 66 69 6c 65 20 70 72 6f 74 63 74 69 6f 6e 20 74 6f 6f 6c } //01 00  Emergency file protction tool
		$a_81_3 = {38 34 73 29 55 48 67 2d 29 49 50 53 76 41 6e 3a 52 23 66 38 30 67 69 28 2e 72 65 73 6f 75 72 63 65 73 } //01 00  84s)UHg-)IPSvAn:R#f80gi(.resources
		$a_81_4 = {53 4e 67 27 47 39 68 5c 5d 5c 5b 76 53 55 75 71 39 71 4a 4f 6b 6b 24 28 53 53 21 2e 72 65 73 6f 75 72 63 65 73 } //00 00  SNg'G9h\]\[vSUuq9qJOkk$(SS!.resources
	condition:
		any of ($a_*)
 
}