
rule Trojan_Win32_Guloader_RPN_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {67 00 6c 00 75 00 6d 00 61 00 63 00 65 00 6f 00 75 00 73 00 2e 00 6c 00 6e 00 6b 00 } //1 glumaceous.lnk
		$a_01_1 = {53 00 68 00 65 00 74 00 6c 00 61 00 6e 00 64 00 73 00 70 00 6f 00 6e 00 79 00 65 00 6e 00 73 00 31 00 30 00 37 00 2e 00 65 00 78 00 65 00 } //1 Shetlandsponyens107.exe
		$a_01_2 = {41 00 72 00 6b 00 69 00 76 00 6b 00 6f 00 70 00 69 00 65 00 72 00 31 00 31 00 34 00 2e 00 69 00 6e 00 69 00 } //1 Arkivkopier114.ini
		$a_01_3 = {68 00 75 00 6e 00 64 00 65 00 68 00 75 00 73 00 65 00 6e 00 65 00 2e 00 65 00 78 00 65 00 } //1 hundehusene.exe
		$a_01_4 = {54 00 4a 00 45 00 52 00 49 00 2e 00 6c 00 6e 00 6b 00 } //1 TJERI.lnk
		$a_01_5 = {44 00 52 00 49 00 46 00 54 00 49 00 47 00 53 00 54 00 45 00 53 00 2e 00 74 00 78 00 74 00 } //1 DRIFTIGSTES.txt
		$a_01_6 = {50 00 55 00 4d 00 4d 00 45 00 4c 00 4c 00 45 00 44 00 2e 00 62 00 6d 00 70 00 } //1 PUMMELLED.bmp
		$a_01_7 = {52 00 64 00 6b 00 6c 00 76 00 65 00 72 00 5c 00 54 00 61 00 6c 00 6c 00 69 00 6e 00 69 00 65 00 72 00 6e 00 65 00 73 00 31 00 34 00 30 00 } //1 Rdklver\Talliniernes140
		$a_01_8 = {66 00 6f 00 72 00 6b 00 6c 00 64 00 65 00 72 00 73 00 5c 00 53 00 75 00 62 00 70 00 65 00 63 00 74 00 69 00 6e 00 61 00 74 00 65 00 32 00 31 00 33 00 } //1 forklders\Subpectinate213
		$a_01_9 = {55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 66 00 6f 00 72 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 } //1 Uninstall\foringerne
		$a_01_10 = {49 00 6e 00 64 00 66 00 6a 00 65 00 6c 00 73 00 65 00 72 00 73 00 31 00 34 00 33 00 } //1 Indfjelsers143
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
rule Trojan_Win32_Guloader_RPN_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 1c 0e 81 f9 bd 00 00 00 81 fa 98 00 00 00 09 1c 08 83 fa 40 81 f9 cc 00 00 00 31 3c 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Guloader_RPN_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 55 08 66 0f 66 ca 0f d8 c3 0f 6b fc eb 11 } //1
		$a_01_1 = {31 0c 06 66 0f 69 c6 9b db e2 66 0f 69 cf eb 0f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}