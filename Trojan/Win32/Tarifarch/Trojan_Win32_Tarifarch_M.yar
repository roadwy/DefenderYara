
rule Trojan_Win32_Tarifarch_M{
	meta:
		description = "Trojan:Win32/Tarifarch.M,SIGNATURE_TYPE_PEHSTR,0b 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 66 69 78 5c 52 65 6c 65 61 73 65 5c 73 66 69 78 2e 70 64 62 } //01 00  sfix\Release\sfix.pdb
		$a_01_1 = {6d 68 74 6d 6c 5c 52 65 6c 65 61 73 65 5c 6d 68 74 6d 6c 2e 70 64 62 } //01 00  mhtml\Release\mhtml.pdb
		$a_01_2 = {61 72 63 5c 52 65 6c 65 61 73 65 5c 61 72 63 2e 70 64 62 } //01 00  arc\Release\arc.pdb
		$a_01_3 = {68 6d 6c 64 31 5c 52 65 6c 65 61 73 65 5c 68 6d 6c 64 31 2e 70 64 62 } //0a 00  hmld1\Release\hmld1.pdb
		$a_01_4 = {2f 00 63 00 65 00 6e 00 74 00 65 00 72 00 63 00 61 00 73 00 68 00 2e 00 72 00 75 00 2f 00 } //0a 00  /centercash.ru/
		$a_01_5 = {2f 00 6d 00 61 00 78 00 69 00 66 00 69 00 6c 00 65 00 73 00 2e 00 72 00 75 00 2f 00 } //0a 00  /maxifiles.ru/
		$a_01_6 = {2f 00 63 00 63 00 64 00 65 00 76 00 32 00 2e 00 72 00 75 00 2f 00 } //00 00  /ccdev2.ru/
	condition:
		any of ($a_*)
 
}