
rule Trojan_Win32_GhostRat_BSA_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 "
		
	strings :
		$a_81_0 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 51 51 47 61 6d 65 2e 65 78 65 } //20 ProgramData\QQGame.exe
		$a_81_1 = {53 54 4d 45 64 69 74 6f 72 2e 44 6f 63 75 6d 65 6e 74 } //1 STMEditor.Document
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1) >=21
 
}