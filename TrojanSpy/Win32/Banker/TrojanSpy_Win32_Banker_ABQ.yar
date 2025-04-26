
rule TrojanSpy_Win32_Banker_ABQ{
	meta:
		description = "TrojanSpy:Win32/Banker.ABQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {eb 07 b2 02 e8 ?? ?? ff ff 8b 45 fc 80 78 5b 00 74 ?? 8b 45 fc 8b 40 44 80 b8 ?? ?? 00 00 01 ?? ?? 8b ?? fc } //1
		$a_00_1 = {69 6e 76 e1 6c 69 64 6f } //1
		$a_00_2 = {65 64 74 73 65 6e 68 61 } //1 edtsenha
		$a_00_3 = {57 69 6e 64 6f 77 73 20 4c 69 76 65 20 4d 65 73 73 65 6e 67 65 72 21 } //1 Windows Live Messenger!
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}