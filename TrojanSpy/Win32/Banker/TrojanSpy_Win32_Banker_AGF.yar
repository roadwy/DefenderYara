
rule TrojanSpy_Win32_Banker_AGF{
	meta:
		description = "TrojanSpy:Win32/Banker.AGF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d8 ba 02 00 00 80 8b c3 e8 ?? ?? ?? ?? 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 33 c9 8b c3 e8 } //1
		$a_01_1 = {5a 4b 4c 4b 5a 4a 42 43 56 4e 42 48 44 59 55 45 52 49 33 36 37 38 36 47 41 4a 53 47 44 4a 47 4a 57 45 } //1 ZKLKZJBCVNBHDYUERI36786GAJSGDJGJWE
		$a_00_2 = {69 6d 67 54 65 6c 61 49 6e 63 69 61 6c 4f 4b 43 6c 69 63 6b } //1 imgTelaIncialOKClick
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}