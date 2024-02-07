
rule Ransom_Win32_FileCoder_PAX_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.PAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //01 00  SELECT * FROM Win32_ShadowCopy
		$a_01_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 62 00 65 00 6d 00 5c 00 57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //01 00  cmd.exe /c C:\Windows\System32\wbem\WMIC.exe shadowcopy
		$a_01_2 = {43 00 3a 00 5c 00 43 00 4f 00 4e 00 54 00 49 00 5f 00 4c 00 4f 00 47 00 2e 00 74 00 78 00 74 00 } //01 00  C:\CONTI_LOG.txt
		$a_01_3 = {54 65 73 74 4c 6f 63 6b 65 72 2e 70 64 62 } //01 00  TestLocker.pdb
		$a_01_4 = {44 45 43 52 59 50 54 5f 4e 4f 54 45 } //00 00  DECRYPT_NOTE
	condition:
		any of ($a_*)
 
}