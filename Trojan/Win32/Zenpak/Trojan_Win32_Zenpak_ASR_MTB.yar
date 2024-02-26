
rule Trojan_Win32_Zenpak_ASR_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 35 34 2e 32 30 34 2e 31 37 39 2e 34 2f 61 31 35 34 2e 33 39 2e 32 33 39 2e 35 36 2e 74 78 74 } //01 00  154.204.179.4/a154.39.239.56.txt
		$a_01_1 = {55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 42 42 42 42 42 42 42 5c 52 65 6c 65 61 73 65 5c 42 42 42 42 42 42 42 2e 70 64 62 } //00 00  Users\Administrator\Desktop\BBBBBBB\Release\BBBBBBB.pdb
	condition:
		any of ($a_*)
 
}