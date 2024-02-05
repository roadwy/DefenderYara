
rule Trojan_Win32_TurtleSyr_A_dha{
	meta:
		description = "Trojan:Win32/TurtleSyr.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 64 65 63 6f 64 65 20 74 68 65 20 70 72 6f 76 69 64 65 64 20 73 68 65 6c 6c 63 6f 64 65 } //01 00 
		$a_01_1 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 49 6e 6a 65 63 74 65 64 2e } //01 00 
		$a_01_2 = {43 6f 75 6c 64 20 4e 6f 74 20 57 72 69 74 65 20 54 6f 20 52 65 6d 6f 74 65 20 50 72 6f 63 65 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}