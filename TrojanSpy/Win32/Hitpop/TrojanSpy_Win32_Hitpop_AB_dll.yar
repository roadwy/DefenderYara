
rule TrojanSpy_Win32_Hitpop_AB_dll{
	meta:
		description = "TrojanSpy:Win32/Hitpop.AB!dll,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1a 00 07 00 00 "
		
	strings :
		$a_02_0 = {43 6f 6d 6d 6f 6e 20 53 74 61 72 74 75 70 00 00 ff ff ff ff [0-25] 2e 6c 6e 6b } //5
		$a_02_1 = {45 78 70 6c 6f 72 65 72 5c 72 75 6e [0-20] 2e 69 6e 69 } //5
		$a_00_2 = {52 55 4e 49 45 50 2e 45 58 45 00 00 ff ff ff ff 0a 00 00 00 4b 52 65 67 45 78 2e 65 78 65 00 00 ff ff ff ff 08 00 00 00 4b 56 58 50 2e 6b 78 70 00 00 00 00 ff ff ff ff 0b 00 00 00 33 36 30 74 72 61 79 2e 65 78 65 } //5
		$a_02_3 = {64 ff 30 64 89 20 8b 45 08 e8 ?? ?? fe ff 8d 45 f0 50 8b 45 f8 e8 ?? ?? fe ff 50 8b 45 fc 50 e8 ?? ?? fe ff 85 c0 } //10
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_00_5 = {48 69 6e 6e 65 72 48 54 4d 4c } //1 HinnerHTML
		$a_00_6 = {48 74 61 72 67 65 74 } //1 Htarget
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_00_2  & 1)*5+(#a_02_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=26
 
}