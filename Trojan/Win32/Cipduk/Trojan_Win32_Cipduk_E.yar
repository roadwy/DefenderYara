
rule Trojan_Win32_Cipduk_E{
	meta:
		description = "Trojan:Win32/Cipduk.E,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 33 32 5c 76 65 72 73 69 6f 6e 2e 6d 75 69 65 6d 33 32 5c 77 63 6e 61 70 69 2e 6d 75 69 } //1 System32\version.muiem32\wcnapi.mui
		$a_01_1 = {63 6f 6d 2f 62 6f 61 72 64 2f 73 69 74 65 6d 61 68 74 74 70 3a 2f 2f 63 68 65 63 6b 69 6e 2e 74 72 61 76 65 6c 73 61 6e 69 67 6e 61 63 69 6f 2e 63 6f 6d 2f } //1 com/board/sitemahttp://checkin.travelsanignacio.com/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}