
rule Trojan_Linux_ElectroRatDrop_A_{
	meta:
		description = "Trojan:Linux/ElectroRatDrop.A!!ElectroRatDrop.A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 67 69 73 74 65 72 55 73 65 72 2e 67 6f } //01 00  registerUser.go
		$a_01_1 = {6f 73 69 6e 66 6f 2e 67 6f } //01 00  osinfo.go
		$a_01_2 = {6d 61 63 68 69 6e 65 69 64 2e 67 6f } //01 00  machineid.go
		$a_01_3 = {64 6f 77 6e 6c 6f 61 64 46 69 6c 65 2e 67 6f } //01 00  downloadFile.go
		$a_01_4 = {62 69 6e 5f 6c 69 6e 75 78 2e 67 6f } //01 00  bin_linux.go
		$a_01_5 = {70 72 6f 63 65 73 73 4b 69 6c 6c 2e 67 6f } //01 00  processKill.go
		$a_01_6 = {73 63 72 65 65 6e 73 68 6f 74 2e 67 6f } //01 00  screenshot.go
		$a_01_7 = {75 70 6c 6f 61 64 46 6f 6c 64 65 72 2e 67 6f } //01 00  uploadFolder.go
		$a_01_8 = {6d 64 77 6f 72 6b 65 72 2e 67 6f } //01 00  mdworker.go
		$a_01_9 = {68 69 64 65 66 69 6c 65 2e 67 6f } //00 00  hidefile.go
	condition:
		any of ($a_*)
 
}