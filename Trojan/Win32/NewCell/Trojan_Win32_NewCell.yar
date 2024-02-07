
rule Trojan_Win32_NewCell{
	meta:
		description = "Trojan:Win32/NewCell,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 25 73 00 00 00 00 45 58 45 00 25 73 5c 00 54 6d 70 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 } //01 00 
		$a_01_1 = {50 72 65 76 69 65 77 50 61 67 65 73 00 00 00 00 53 65 74 74 69 6e 67 00 } //02 00 
		$a_01_2 = {65 3a 5c 50 72 6f 6a 65 63 74 5c 6e 65 77 63 65 6c 6c 5c 63 6c 69 70 } //01 00  e:\Project\newcell\clip
		$a_01_3 = {4d 69 63 72 6f 73 6f 66 74 40 20 57 69 6e 64 6f 77 73 40 20 4f 70 65 72 61 74 69 6e 67 20 53 79 73 74 65 6d } //00 00  Microsoft@ Windows@ Operating System
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NewCell_2{
	meta:
		description = "Trojan:Win32/NewCell,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 79 6c 69 6e 76 65 72 6d 69 6c 69 6f 6e } //01 00  kylinvermilion
		$a_01_1 = {62 61 63 6b 73 65 72 76 65 72 } //01 00  backserver
		$a_01_2 = {6d 61 69 6e 73 65 72 76 65 72 } //01 00  mainserver
		$a_01_3 = {43 6f 6d 6d 61 6e 64 76 65 72 73 69 6f 6e } //01 00  Commandversion
		$a_01_4 = {46 69 6c 74 65 72 76 65 72 73 69 6f 6e } //01 00  Filterversion
		$a_01_5 = {61 6c 74 65 72 66 61 76 6f 72 69 74 65 } //01 00  alterfavorite
		$a_01_6 = {61 64 64 73 68 6f 74 63 75 74 } //01 00  addshotcut
		$a_01_7 = {73 65 74 68 6f 6d 65 } //05 00  sethome
		$a_01_8 = {68 74 74 70 3a 2f 2f 73 65 2e 6e 65 77 63 65 6c 6c 2e 63 6e 2f 53 65 72 76 69 63 65 2e 61 73 6d 78 } //05 00  http://se.newcell.cn/Service.asmx
		$a_01_9 = {65 3a 5c 50 72 6f 6a 65 63 74 5c 6e 65 77 63 65 6c 6c 5c 73 76 63 } //00 00  e:\Project\newcell\svc
	condition:
		any of ($a_*)
 
}