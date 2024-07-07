
rule Trojan_BAT_AsyncRat_NE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 2c 58 1c 13 0f 90 01 02 ff ff ff 08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 09 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AsyncRat_NE_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 15 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0a 06 58 0b 72 90 01 01 00 00 70 12 01 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 90 00 } //5
		$a_01_1 = {46 6c 61 70 70 79 5f 42 69 72 64 5f 57 69 6e 64 6f 77 73 5f 46 6f 72 6d } //1 Flappy_Bird_Windows_Form
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AsyncRat_NE_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRat.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 7a 64 6f 4b 52 41 63 4e 63 75 73 6c 6b 57 70 6a 74 42 42 } //4 AzdoKRAcNcuslkWpjtBB
		$a_01_1 = {4a 77 4b 59 52 66 62 56 47 6a 72 4b 66 54 69 76 4e 72 46 71 } //4 JwKYRfbVGjrKfTivNrFq
		$a_01_2 = {57 33 66 61 73 63 61 63 61 78 63 } //3 W3fascacaxc
		$a_01_3 = {63 72 79 70 74 65 64 2e 65 78 65 } //3 crypted.exe
		$a_01_4 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //3 Debugger Detected
		$a_01_5 = {4c 6f 6d 69 6e 65 72 73 } //2 Lominers
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2) >=19
 
}