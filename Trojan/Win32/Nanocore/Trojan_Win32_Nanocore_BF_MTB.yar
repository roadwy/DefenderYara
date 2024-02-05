
rule Trojan_Win32_Nanocore_BF_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 0b 00 00 0a 00 "
		
	strings :
		$a_80_0 = {77 69 6e 72 61 72 73 66 78 6d 61 70 70 69 6e 67 66 69 6c 65 2e 74 6d 70 } //winrarsfxmappingfile.tmp  0a 00 
		$a_80_1 = {47 45 54 50 41 53 53 57 4f 52 44 31 } //GETPASSWORD1  0a 00 
		$a_80_2 = {5f 5f 74 6d 70 5f 72 61 72 5f 73 66 78 5f 61 63 63 65 73 73 5f 63 68 65 63 6b 5f 25 75 } //__tmp_rar_sfx_access_check_%u  0a 00 
		$a_02_3 = {53 00 65 00 74 00 75 00 70 00 3d 00 90 02 0a 2e 00 70 00 69 00 66 00 90 00 } //0a 00 
		$a_02_4 = {53 65 74 75 70 3d 90 02 0a 2e 70 69 66 90 00 } //0a 00 
		$a_80_5 = {2e 70 64 66 } //.pdf  0a 00 
		$a_80_6 = {53 69 6c 65 6e 74 3d 31 } //Silent=1  0a 00 
		$a_80_7 = {45 78 74 72 61 63 74 69 6e 67 20 66 69 6c 65 73 20 74 6f 20 43 3a 5c 20 66 6f 6c 64 65 72 } //Extracting files to C:\ folder  0a 00 
		$a_80_8 = {50 61 74 68 3d 25 74 65 6d 70 25 5c } //Path=%temp%\  0a 00 
		$a_80_9 = {41 52 61 72 48 74 6d 6c 43 6c 61 73 73 4e 61 6d 65 } //ARarHtmlClassName  0a 00 
		$a_80_10 = {43 72 79 70 74 50 72 6f 74 65 63 74 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64 } //CryptProtectMemory failed  00 00 
	condition:
		any of ($a_*)
 
}