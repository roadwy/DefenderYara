
rule Trojan_Win32_Zenpak_GPL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {6c 69 66 65 68 4d 6f 76 69 6e 67 2e 73 65 61 73 6f 6e 73 58 76 57 65 72 65 4b } //01 00  lifehMoving.seasonsXvWereK
		$a_81_1 = {54 77 69 6e 67 65 64 31 67 72 65 61 74 65 72 2e 77 73 65 61 76 6f 69 64 72 } //01 00  Twinged1greater.wseavoidr
		$a_81_2 = {66 72 75 69 74 74 6b 74 6f 67 65 74 68 65 72 77 69 74 68 6f 75 74 5a 62 65 67 69 6e 6e 69 6e 67 } //01 00  fruittktogetherwithoutZbeginning
		$a_81_3 = {51 6c 69 76 69 6e 67 67 69 76 65 6e 67 72 65 61 74 73 65 61 73 65 65 64 67 69 76 65 7a } //00 00  Qlivinggivengreatseaseedgivez
	condition:
		any of ($a_*)
 
}