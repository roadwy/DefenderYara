
rule Ransom_Win32_Filecoder_NBA_ibt{
	meta:
		description = "Ransom:Win32/Filecoder.NBA!ibt,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {46 75 6e 63 74 69 6f 6e 20 64 65 74 65 63 74 65 64 3a 20 25 73 3a 25 73 } //Function detected: %s:%s  1
		$a_80_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //expand 32-byte k  1
		$a_80_2 = {5f 5f 44 45 43 52 59 50 54 5f 4e 4f 54 45 5f 5f } //__DECRYPT_NOTE__  1
		$a_80_3 = {4e 42 41 5f 4c 4f 47 2e 74 78 74 } //NBA_LOG.txt  1
		$a_80_4 = {55 6e 68 6f 6f 6b 20 6d 6f 64 75 6c 65 3a 20 25 6e 74 64 6c 6c 2e 64 6c 6c } //Unhook module: %ntdll.dll  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}