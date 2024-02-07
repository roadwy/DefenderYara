
rule Trojan_Win32_Horros_LK_MTB{
	meta:
		description = "Trojan:Win32/Horros.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 6c 65 61 73 65 5c 46 69 6c 65 45 6e 63 72 79 70 74 65 72 2e 70 64 62 } //01 00  Release\FileEncrypter.pdb
		$a_01_1 = {2e 00 68 00 6f 00 72 00 72 00 6f 00 73 00 } //01 00  .horros
		$a_01_2 = {47 65 74 46 69 6c 65 73 41 6e 64 45 6e 63 72 79 70 74 } //01 00  GetFilesAndEncrypt
		$a_01_3 = {46 69 6c 65 45 6e 63 72 79 70 74 } //00 00  FileEncrypt
	condition:
		any of ($a_*)
 
}