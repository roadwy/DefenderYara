
rule Ransom_Win32_Expelcod_A{
	meta:
		description = "Ransom:Win32/Expelcod.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 45 6e 63 72 79 70 74 6f 72 } //01 00  AutoEncryptor
		$a_01_1 = {55 00 73 00 65 00 72 00 46 00 69 00 6c 00 65 00 73 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  UserFilesLocker.exe
		$a_01_2 = {5f 00 5f 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 2e 00 70 00 69 00 6e 00 66 00 6f 00 } //01 00  __encrypt.pinfo
		$a_01_3 = {2e 00 45 00 4e 00 43 00 52 00 } //00 00  .ENCR
	condition:
		any of ($a_*)
 
}