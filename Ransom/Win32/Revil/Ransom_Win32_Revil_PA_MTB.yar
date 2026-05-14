
rule Ransom_Win32_Revil_PA_MTB{
	meta:
		description = "Ransom:Win32/Revil.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 46 00 49 00 58 00 54 00 } //1 .FIXT
		$a_01_1 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 68 00 74 00 61 00 } //1 readme.hta
		$a_01_2 = {73 00 74 00 61 00 72 00 74 00 62 00 2e 00 62 00 61 00 74 00 } //1 startb.bat
		$a_01_3 = {59 00 4f 00 55 00 52 00 5f 00 46 00 49 00 4c 00 45 00 53 00 5f 00 41 00 52 00 45 00 5f 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 2e 00 54 00 58 00 54 00 } //3 YOUR_FILES_ARE_ENCRYPTED.TXT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3) >=6
 
}