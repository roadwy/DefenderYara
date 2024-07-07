
rule Ransom_MSIL_Genasom_R_MSR{
	meta:
		description = "Ransom:MSIL/Genasom.R!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 5c 45 78 65 5c 53 74 61 74 69 6b 20 56 65 72 73 69 6f 6e 5c 43 72 79 70 74 65 72 4c 61 73 74 56 65 72 73 69 6f 6e 5c 43 72 79 70 74 65 72 4c 61 73 74 56 65 72 73 69 6f 6e 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4a 61 76 61 45 6d 62 65 64 65 64 4c 69 62 72 61 72 79 2e 70 64 62 } //3 Ransom\Exe\Statik Version\CrypterLastVersion\CrypterLastVersion\obj\Release\JavaEmbededLibrary.pdb
		$a_01_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 44 00 65 00 76 00 69 00 63 00 65 00 43 00 68 00 61 00 6e 00 67 00 65 00 45 00 76 00 65 00 6e 00 74 00 20 00 57 00 48 00 45 00 52 00 45 00 20 00 45 00 76 00 65 00 6e 00 74 00 54 00 79 00 70 00 65 00 20 00 3d 00 20 00 32 00 } //1 SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 2
		$a_01_2 = {2e 00 63 00 69 00 70 00 68 00 65 00 72 00 65 00 64 00 } //1 .ciphered
		$a_01_3 = {45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 } //1 ENCRYPTED
		$a_01_4 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_5 = {55 6e 61 75 74 68 6f 72 69 7a 65 64 41 63 63 65 73 73 } //1 UnauthorizedAccess
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}