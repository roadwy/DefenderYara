
rule Trojan_Win32_Modimer_A{
	meta:
		description = "Trojan:Win32/Modimer.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 73 68 61 6e 2e 62 69 74 2f 73 74 61 72 74 2e 70 68 70 00 68 74 74 70 3a 2f 2f 67 6f 73 68 61 6e 2e 6f 6e 6c 69 6e 65 2f 73 74 61 72 74 2e 70 68 70 00 00 68 74 74 70 3a 2f 2f 6d 65 64 69 61 2d 67 65 74 2e 62 69 74 2f 73 74 61 72 74 2e 70 68 70 00 00 68 74 74 70 3a 2f 2f 6d 65 64 6c 61 2d 67 65 74 2e 63 6f 6d 2f 73 74 61 72 74 2e } //01 00 
		$a_01_1 = {2f 6d 79 2e 64 61 74 00 52 55 4e 00 48 41 53 48 } //00 00 
	condition:
		any of ($a_*)
 
}