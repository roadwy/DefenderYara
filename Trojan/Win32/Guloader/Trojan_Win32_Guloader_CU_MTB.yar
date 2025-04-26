
rule Trojan_Win32_Guloader_CU_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4f 76 61 72 69 6f 63 65 6e 74 65 73 69 73 31 38 33 2e 69 6e 76 } //1 Ovariocentesis183.inv
		$a_01_1 = {54 6e 6b 65 62 6f 6b 73 65 6e 65 73 5c 6b 6a 65 72 73 74 65 6e 73 5c 73 6f 61 70 62 61 72 6b } //1 Tnkeboksenes\kjerstens\soapbark
		$a_01_2 = {43 6f 65 78 63 68 61 6e 67 65 61 62 6c 65 32 33 37 2e 64 6c 6c } //1 Coexchangeable237.dll
		$a_01_3 = {69 6d 70 69 6f 75 73 5c 73 63 61 62 72 6f 75 73 5c 62 61 7a 6f 6f 6b 61 6d 65 6e } //1 impious\scabrous\bazookamen
		$a_01_4 = {63 72 61 64 6c 65 6c 69 6b 65 2e 62 72 79 } //1 cradlelike.bry
		$a_01_5 = {4d 65 73 63 61 6c 32 34 36 5c 55 6e 69 6e 73 74 61 6c 6c 5c 70 72 6f 6a 65 6b 74 6f 70 67 61 76 65 72 73 5c 69 6f 64 68 79 64 72 69 63 } //1 Mescal246\Uninstall\projektopgavers\iodhydric
		$a_01_6 = {6e 6f 6e 70 6c 75 73 73 69 6e 67 2e 62 6c 6f } //1 nonplussing.blo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}