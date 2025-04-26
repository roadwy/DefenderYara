
rule TrojanSpy_Win32_Banker_ABR{
	meta:
		description = "TrojanSpy:Win32/Banker.ABR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {eb 07 b2 02 e8 ?? ?? ff ff 8b 45 fc 80 78 5b 00 74 ?? 8b 45 fc 8b 40 44 80 b8 ?? ?? 00 00 01 ?? ?? 8b ?? fc } //2
		$a_00_1 = {53 69 6c 65 6e 74 } //1 Silent
		$a_00_2 = {2a 75 70 2a 2e 2a 65 78 2a 65 } //1 *up*.*ex*e
		$a_00_3 = {73 65 6e 68 61 } //1 senha
		$a_00_4 = {42 72 61 23 64 65 73 23 63 6f } //1 Bra#des#co
		$a_00_5 = {62 72 61 64 65 73 63 6f 20 69 6e 74 65 72 6e 65 74 20 62 61 6e 6b 69 6e 67 } //1 bradesco internet banking
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}