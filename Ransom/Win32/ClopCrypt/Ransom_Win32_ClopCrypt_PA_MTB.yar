
rule Ransom_Win32_ClopCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/ClopCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c1 00 20 00 00 89 4d 90 01 01 8b 95 90 01 02 ff ff 2b 55 98 89 95 90 01 02 ff ff 8b 45 90 01 01 99 b9 00 c0 0f 00 f7 f9 89 45 90 01 01 8b 55 90 01 01 81 c2 00 10 00 00 89 55 90 01 01 8b 85 90 01 02 ff ff 33 85 90 01 02 ff ff 89 85 90 01 02 ff ff 8b 4d 90 01 01 81 c1 00 f0 ff 0f 89 4d 90 01 01 c1 85 90 01 02 ff ff 07 8b 55 90 01 01 81 ea cc 34 00 00 89 55 90 01 01 8b 85 90 01 02 ff ff 33 85 90 01 02 ff ff 89 85 90 01 02 ff ff 8b 4d 90 01 01 8b 55 90 01 01 8b 85 90 01 02 ff ff 89 04 8a e9 90 01 02 ff ff 90 00 } //00 00 
		$a_00_1 = {78 } //df 00  x
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_ClopCrypt_PA_MTB_2{
	meta:
		description = "Ransom:Win32/ClopCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 62 00 65 00 6d 00 5c 00 57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 22 00 49 00 44 00 3d 00 27 00 25 00 73 00 27 00 22 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 } //01 00  cmd.exe /c C:\Windows\System32\wbem\WMIC.exe shadowcopy where "ID='%s'" delete
		$a_01_1 = {25 00 73 00 5c 00 21 00 41 00 5f 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 54 00 58 00 54 00 } //01 00  %s\!A_READ_ME.TXT
		$a_01_2 = {2e 00 43 00 49 00 5f 00 30 00 50 00 } //00 00  .CI_0P
	condition:
		any of ($a_*)
 
}