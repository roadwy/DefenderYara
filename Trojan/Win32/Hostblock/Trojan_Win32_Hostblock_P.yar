
rule Trojan_Win32_Hostblock_P{
	meta:
		description = "Trojan:Win32/Hostblock.P,SIGNATURE_TYPE_PEHSTR,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //0a 00 
		$a_01_1 = {31 32 37 2e 30 2e 30 2e 31 20 77 77 77 2e 76 69 64 65 6f 67 61 67 61 2e 6c 74 } //0a 00 
		$a_01_2 = {31 32 37 2e 30 2e 30 2e 31 20 76 69 64 65 6f 67 61 67 61 2e 6c 74 } //0a 00 
		$a_01_3 = {ff ff ff ff 0b 00 00 00 31 32 37 2e 30 2e 30 2e 31 20 63 00 ff ff ff ff 07 00 00 00 2e 6f 6e 65 2e 6c 74 00 ff ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}