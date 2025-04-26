
rule Trojan_Win32_Emotet_BZ{
	meta:
		description = "Trojan:Win32/Emotet.BZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 2e 50 64 62 } //1 $.Pdb
		$a_01_1 = {68 57 45 48 57 23 40 48 4a 45 52 4b 4a 45 52 4a 45 52 } //1 hWEHW#@HJERKJERJER
		$a_00_2 = {57 00 65 00 72 00 4d 00 67 00 72 00 } //1 WerMgr
		$a_00_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 ae 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 ae 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}