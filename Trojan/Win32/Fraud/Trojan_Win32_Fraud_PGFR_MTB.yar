
rule Trojan_Win32_Fraud_PGFR_MTB{
	meta:
		description = "Trojan:Win32/Fraud.PGFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 20 22 43 3a 5c 54 45 4d 50 5c 63 6c 65 61 6e 5f 70 6f 6c 69 63 69 65 73 2e 70 73 31 } //powershell.exe  -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\TEMP\clean_policies.ps1  5
		$a_02_1 = {68 00 74 00 74 00 70 00 [0-02] 3a 00 2f 00 2f 00 [0-3f] 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 61 00 64 00 6f 00 72 00 2f 00 74 00 6f 00 6b 00 65 00 6e 00 2e 00 74 00 78 00 74 00 3f 00 } //5
		$a_02_2 = {68 74 00 74 00 70 [0-02] 3a 2f 2f [0-3f] 2f 69 6e 73 74 61 6c 61 64 6f 72 2f 74 6f 6b 65 6e 2e 74 78 74 3f } //5
	condition:
		((#a_80_0  & 1)*5+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5) >=10
 
}