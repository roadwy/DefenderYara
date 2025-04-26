
rule VirTool_Win32_Injector_FU{
	meta:
		description = "VirTool:Win32/Injector.FU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 99 f7 7d 0c 8b 45 08 0f be 0c 10 8b 55 10 03 55 fc 0f be 02 33 c1 8b 4d 10 03 4d fc 88 01 } //1
		$a_01_1 = {5c 78 6d 63 72 79 70 74 6f 2e 70 64 62 } //-100 \xmcrypto.pdb
		$a_00_2 = {68 72 5f 64 65 63 72 79 70 74 6f 72 5c 62 69 6e 5c 48 52 44 65 63 72 79 70 74 65 72 2e 70 64 62 } //-100 hr_decryptor\bin\HRDecrypter.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*-100+(#a_00_2  & 1)*-100) >=1
 
}