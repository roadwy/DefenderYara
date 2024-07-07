
rule Ransom_Java_Lanifynop_A_ibt{
	meta:
		description = "Ransom:Java/Lanifynop.A!ibt,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 72 77 2c 2e 70 65 66 2c 2e 70 74 78 2c 2e 72 33 64 2c 2e 72 77 32 2c 2e 72 77 6c 2c 2e 72 61 77 2c 2e 72 61 66 2c 2e 6f 72 66 2c 2e 6e 72 77 2c 2e 6d 72 77 72 65 66 2c 2e 6d 65 66 2c 2e 65 72 66 2c 2e 6b 64 63 2c 2e 64 63 72 2c 2e 63 72 32 2c 2e 63 72 77 2c 2e 62 61 79 2c 2e 73 72 32 2c 2e 73 72 66 2c 2e 61 72 77 2c 2e 33 66 72 2c 2e 64 6e 67 2c 2e 6a 70 65 2c 2e 6a 70 67 } //1 srw,.pef,.ptx,.r3d,.rw2,.rwl,.raw,.raf,.orf,.nrw,.mrwref,.mef,.erf,.kdc,.dcr,.cr2,.crw,.bay,.sr2,.srf,.arw,.3fr,.dng,.jpe,.jpg
		$a_01_1 = {45 6e 63 72 79 70 74 69 6e 67 20 66 69 6c 65 3a 20 25 73 25 6e } //1 Encrypting file: %s%n
		$a_01_2 = {52 45 41 44 4d 45 5f 66 69 6c 65 73 2e 74 78 74 } //1 README_files.txt
		$a_01_3 = {6a 61 76 61 2f 73 65 63 75 72 69 74 79 2f 53 65 63 75 72 65 52 61 6e 64 6f 6d } //1 java/security/SecureRandom
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}