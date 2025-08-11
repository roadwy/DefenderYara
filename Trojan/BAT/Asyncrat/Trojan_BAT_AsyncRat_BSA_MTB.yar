
rule Trojan_BAT_AsyncRat_BSA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_81_0 = {53 6b 69 70 70 69 6e 67 20 41 6e 6e 61 62 65 6c 6c 65 2e 65 78 65 } //10 Skipping Annabelle.exe
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //1 powershell.exe
		$a_81_2 = {45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 } //1 ExecutionPolicy Bypass -File
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}