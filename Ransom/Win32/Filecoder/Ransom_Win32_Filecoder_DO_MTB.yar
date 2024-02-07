
rule Ransom_Win32_Filecoder_DO_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //01 00  cmd.exe /c vssadmin Delete Shadows /All /Quiet
		$a_81_1 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 46 69 6c 65 73 } //01 00  How To Decrypt Files
		$a_81_2 = {40 74 75 74 61 2e 69 6f } //01 00  @tuta.io
		$a_81_3 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 53 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //01 00  ALL YOUR FILES HAS BEEN ENCRYPTED
		$a_81_4 = {44 6f 6e 27 74 20 66 69 6e 64 20 79 6f 75 72 20 62 61 63 6b 75 70 73 3f 20 74 68 65 79 20 68 61 76 65 20 62 65 65 6e 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 } //00 00  Don't find your backups? they have been Successfully encrypted
	condition:
		any of ($a_*)
 
}