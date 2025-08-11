
rule Trojan_Win32_ClipBanker_ACI_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.ACI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {be 01 00 00 00 8d 45 fc 50 68 06 00 02 00 6a 00 68 21 81 40 00 68 01 00 00 80 } //1
		$a_03_1 = {53 56 57 33 db 8b 75 08 8b fb 8b c7 66 83 c0 78 0f b7 d0 52 56 e8 ?? ?? ?? ?? 66 81 c7 82 00 0f b7 cf } //2
		$a_01_2 = {4e 50 2d 30 30 30 30 2d 30 30 30 30 30 30 30 2d 30 30 30 30 2d 30 43 61 4f 72 52 41 65 } //3 NP-0000-0000000-0000-0CaOrRAe
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 65 64 69 73 79 73 5c 65 4e 6f 74 65 50 61 64 } //4 Software\edisys\eNotePad
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4) >=10
 
}