
rule Trojan_Win32_Flatterly_A_dha{
	meta:
		description = "Trojan:Win32/Flatterly.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 3a 67 6f 6f 67 6c 65 63 68 72 6f 6d 65 75 70 64 61 74 65 } //01 00  ::googlechromeupdate
		$a_01_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 74 00 2e 00 74 00 78 00 74 00 } //01 00  C:\ProgramData\t.txt
		$a_01_2 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 21 00 } //01 00  Execute!
		$a_01_3 = {44 00 4e 00 53 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 64 00 6c 00 6c 00 } //01 00  DNSClient.dll
		$a_01_4 = {44 00 4e 00 53 00 43 00 6c 00 69 00 65 00 6e 00 2e 00 65 00 78 00 65 00 } //00 00  DNSClien.exe
	condition:
		any of ($a_*)
 
}