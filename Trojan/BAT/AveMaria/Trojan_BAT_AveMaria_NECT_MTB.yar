
rule Trojan_BAT_AveMaria_NECT_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 08 07 6f 90 01 01 00 00 0a 08 18 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 02 50 16 02 50 8e 69 6f 90 01 01 00 00 0a 2a 90 00 } //10
		$a_01_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 5c 00 76 00 31 00 2e 00 30 00 5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //5 C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}