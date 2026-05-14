
rule Trojan_Win64_RustyStealer_NSA_MTB{
	meta:
		description = "Trojan:Win64/RustyStealer.NSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {4d 63 41 66 65 65 4d 63 41 66 65 65 5c 45 6e 64 70 6f 69 6e 74 20 53 65 63 75 72 69 74 79 } //1 McAfeeMcAfee\Endpoint Security
		$a_81_1 = {50 61 6e 64 61 20 53 65 63 75 72 69 74 79 50 61 6e 64 61 50 61 6e 64 61 20 53 65 63 75 72 69 74 79 5c 50 72 6f 74 65 63 74 69 6f 6e } //1 Panda SecurityPandaPanda Security\Protection
		$a_81_2 = {43 79 6c 61 6e 63 65 43 79 6c 61 6e 63 65 50 52 4f 54 45 43 54 43 79 6c 61 6e 63 65 5c 44 65 73 6b 74 6f 70 } //1 CylanceCylancePROTECTCylance\Desktop
		$a_81_3 = {45 53 45 54 45 53 45 54 20 53 65 63 75 72 69 74 79 45 53 45 54 5c 45 53 45 54 20 53 65 63 75 72 69 74 79 45 53 45 54 5c 45 53 45 54 20 45 6e 64 70 6f 69 6e 74 20 53 65 63 75 72 69 74 79 } //1 ESETESET SecurityESET\ESET SecurityESET\ESET Endpoint Security
		$a_81_4 = {41 76 61 73 74 41 76 61 73 74 20 41 6e 74 69 76 69 72 75 73 41 56 41 53 54 20 53 6f 66 74 77 61 72 65 5c 41 76 61 73 74 41 56 41 53 54 20 53 6f 66 74 77 61 72 65 5c 50 65 72 73 69 73 74 65 6e 74 20 44 61 74 61 5c 41 76 61 73 74 5c 61 76 61 73 74 35 2e 69 6e 69 } //1 AvastAvast AntivirusAVAST Software\AvastAVAST Software\Persistent Data\Avast\avast5.ini
		$a_81_5 = {4e 6f 20 64 65 74 65 63 74 69 6f 6e 73 20 66 6f 75 6e 64 50 52 4f 47 52 41 4d 44 41 54 41 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 } //2 No detections foundPROGRAMDATAC:\ProgramData
		$a_81_6 = {4d 61 6c 77 61 72 65 62 79 74 65 73 4d 61 6c 77 61 72 65 62 79 74 65 73 5c 4d 42 41 4d 53 65 72 76 69 63 65 } //1 MalwarebytesMalwarebytes\MBAMService
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*2+(#a_81_6  & 1)*1) >=8
 
}