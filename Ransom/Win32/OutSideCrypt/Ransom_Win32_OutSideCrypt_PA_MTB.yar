
rule Ransom_Win32_OutSideCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/OutSideCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 63 00 72 00 79 00 70 00 74 00 } //01 00  .crypt
		$a_01_1 = {5c 73 70 6f 6f 6c 73 73 76 2e 70 64 62 } //01 00  \spoolssv.pdb
		$a_01_2 = {52 45 41 44 2e 74 78 74 } //01 00  READ.txt
		$a_01_3 = {41 4c 4c 20 44 41 54 41 20 49 53 20 45 4e 43 52 59 50 54 45 44 } //01 00  ALL DATA IS ENCRYPTED
		$a_01_4 = {72 64 20 2f 71 20 2f 73 20 22 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c 24 52 65 63 79 63 6c 65 2e 62 69 6e } //00 00  rd /q /s "%systemdrive%\$Recycle.bin
	condition:
		any of ($a_*)
 
}