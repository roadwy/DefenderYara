
rule Trojan_BAT_CryptInject_BA{
	meta:
		description = "Trojan:BAT/CryptInject.BA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 45 00 78 00 4d 00 69 00 6e 00 65 00 } //1
		$a_01_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4d 00 69 00 6e 00 65 00 73 00 77 00 65 00 65 00 70 00 65 00 72 00 20 00 49 00 6d 00 70 00 72 00 6f 00 76 00 65 00 64 00 } //1 Microsoft Minesweeper Improved
		$a_01_2 = {41 00 74 00 72 00 6f 00 63 00 69 00 74 00 79 00 20 00 49 00 6e 00 63 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Atrocity Incorporation
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}