
rule BrowserModifier_Win32_Troboxi{
	meta:
		description = "BrowserModifier:Win32/Troboxi,SIGNATURE_TYPE_PEHSTR_EXT,6e 00 6e 00 04 00 00 "
		
	strings :
		$a_01_0 = {29 35 35 31 7b 6e 6e 2a 34 33 32 6f 33 34 6e 28 2f 25 24 39 } //10 )551{nn*432o34n(/%$9
		$a_01_1 = {68 74 74 70 3a 2f 2f 6b 75 72 73 2e 72 75 2f 69 6e 64 65 78 } //5 http://kurs.ru/index
		$a_01_2 = {31 37 36 2e 39 2e 31 35 37 2e 31 34 33 2f 63 6f 75 6e 74 65 72 } //5 176.9.157.143/counter
		$a_03_3 = {59 50 6a 01 6a 00 8d 45 d8 50 e8 ?? ?? 00 00 59 50 ff 75 a8 ff 15 ?? ?? 40 00 ff 75 a8 ff 15 ?? ?? 40 00 5f 5e 5b c9 c3 } //100
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_03_3  & 1)*100) >=110
 
}