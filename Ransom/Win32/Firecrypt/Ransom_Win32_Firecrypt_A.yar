
rule Ransom_Win32_Firecrypt_A{
	meta:
		description = "Ransom:Win32/Firecrypt.A,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2e 00 66 00 69 00 72 00 65 00 63 00 72 00 79 00 70 00 74 00 } //0a 00  .firecrypt
		$a_00_1 = {2e 00 64 00 6f 00 63 00 78 00 00 09 2e 00 63 00 73 00 76 00 00 09 2e 00 73 00 71 00 6c 00 } //0a 00  .docxऀ.csvऀ.sql
		$a_00_2 = {5c 00 53 00 79 00 73 00 57 00 69 00 6e 00 33 00 32 00 } //00 00  \SysWin32
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Firecrypt_A_2{
	meta:
		description = "Ransom:Win32/Firecrypt.A,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2e 00 66 00 69 00 72 00 65 00 63 00 72 00 79 00 70 00 74 00 } //0a 00  .firecrypt
		$a_01_1 = {2e 00 64 00 6f 00 63 00 78 00 00 09 2e 00 63 00 73 00 76 00 00 09 2e 00 73 00 71 00 6c 00 } //0a 00  .docxऀ.csvऀ.sql
		$a_01_2 = {5c 00 53 00 79 00 73 00 57 00 69 00 6e 00 33 00 32 00 } //00 00  \SysWin32
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Firecrypt_A_3{
	meta:
		description = "Ransom:Win32/Firecrypt.A,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 42 6c 65 65 64 47 72 65 65 6e 2e 70 64 62 } //0a 00  \BleedGreen.pdb
		$a_01_1 = {41 00 45 00 53 00 32 00 35 00 36 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 65 00 57 00 61 00 72 00 65 00 } //0a 00  AES256 RansomeWare
		$a_01_2 = {44 00 44 00 6f 00 73 00 65 00 72 00 2e 00 2e 00 2e 00 20 00 28 00 42 00 65 00 63 00 61 00 75 00 73 00 65 00 } //00 00  DDoser... (Because
	condition:
		any of ($a_*)
 
}