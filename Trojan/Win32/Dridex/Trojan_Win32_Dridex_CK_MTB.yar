
rule Trojan_Win32_Dridex_CK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.CK!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {23 74 68 65 77 61 6c 6b 65 72 7a 34 62 6f 74 68 4e 6f 75 } //1 #thewalkerz4bothNou
		$a_01_1 = {43 61 74 65 67 6f 72 79 3a 47 6f 6f 67 6c 65 63 6f 6d 70 75 74 65 72 4a 50 } //1 Category:GooglecomputerJP
		$a_01_2 = {30 72 45 78 70 6c 6f 72 65 72 33 6a 50 5a 32 39 2c 61 62 79 } //1 0rExplorer3jPZ29,aby
		$a_01_3 = {52 68 46 69 72 65 66 6f 78 2c 33 4f 6e 4f 47 6f 6f 67 6c 65 4c 74 } //1 RhFirefox,3OnOGoogleLt
		$a_01_4 = {62 6c 6f 67 67 65 72 73 43 68 72 6f 6d 65 78 4f 77 61 73 50 4e } //1 bloggersChromexOwasPN
		$a_01_5 = {47 69 72 65 6e 64 65 72 69 6e 67 6d 65 64 34 61 76 61 69 6c 61 62 6c 65 78 78 72 65 6c 65 61 73 65 } //1 Girenderingmed4availablexxrelease
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}