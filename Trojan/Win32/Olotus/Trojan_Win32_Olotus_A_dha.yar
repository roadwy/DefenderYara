
rule Trojan_Win32_Olotus_A_dha{
	meta:
		description = "Trojan:Win32/Olotus.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 3a 5c 50 72 6f 6a 65 63 74 47 69 74 5c 53 48 45 4c 4c 5c 42 72 6f 6b 65 6e 53 68 65 69 6c 64 5c 42 72 6f 6b 65 6e 53 68 69 65 6c 64 50 72 6a 5c 42 69 6e 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 44 6c 6c 45 78 70 6f 72 74 78 38 36 2e 70 64 62 } //1 E:\ProjectGit\SHELL\BrokenSheild\BrokenShieldPrj\Bin\x86\Release\DllExportx86.pdb
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 4d 65 69 73 74 65 72 5c 44 6f 63 75 6d 65 6e 74 73 5c 50 72 6f 6a 65 63 74 73 5c 42 72 6f 6b 65 6e 53 68 69 65 6c 64 5c 42 69 6e 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 42 72 6f 6b 65 6e 53 68 69 65 6c 64 2e 70 64 62 } //1 C:\Users\Meister\Documents\Projects\BrokenShield\Bin\x86\Release\BrokenShield.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}