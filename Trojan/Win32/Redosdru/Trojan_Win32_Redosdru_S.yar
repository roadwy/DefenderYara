
rule Trojan_Win32_Redosdru_S{
	meta:
		description = "Trojan:Win32/Redosdru.S,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {7e 0e 8a 0c 90 01 01 80 f1 90 01 01 88 0c 90 01 01 40 3b 90 01 01 7c f2 90 00 } //01 00 
		$a_03_1 = {74 23 8a 8a 90 01 04 bf 90 01 04 80 f1 90 01 01 33 c0 88 8a 90 01 04 83 c9 ff 42 f2 ae f7 d1 49 3b d1 72 dd 90 00 } //01 00 
		$a_01_2 = {b9 00 5c 26 05 99 f7 f9 b8 59 be 90 4a } //02 00 
		$a_00_3 = {46 6c 61 67 3a 25 73 20 4e 61 6d 65 3a 25 73 20 49 50 3a 25 73 20 4f 53 3a 25 73 } //01 00 
		$a_00_4 = {25 00 73 00 44 00 61 00 79 00 25 00 73 00 48 00 6f 00 75 00 72 00 25 00 73 00 4d 00 69 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}