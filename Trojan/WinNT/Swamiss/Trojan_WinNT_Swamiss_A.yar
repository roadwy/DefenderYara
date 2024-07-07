
rule Trojan_WinNT_Swamiss_A{
	meta:
		description = "Trojan:WinNT/Swamiss.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 53 00 79 00 73 00 4d 00 6f 00 6e 00 00 00 } //1
		$a_00_1 = {8a 01 6a 1a 3c 61 5f 0f be c0 7c 0b 83 e8 4a 99 f7 ff 80 c2 61 eb 09 83 e8 2a 99 f7 ff 80 c2 41 88 11 41 80 39 00 75 d8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}