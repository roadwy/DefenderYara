
rule HackTool_Win32_ICQFlood_A{
	meta:
		description = "HackTool:Win32/ICQFlood.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 43 51 20 46 6c 6f 6f 64 65 72 20 62 79 20 6c 2d 6c 30 30 } //01 00 
		$a_00_1 = {49 43 51 46 6c 6f 6f 64 65 72 20 62 79 20 48 30 30 4b } //02 00 
		$a_02_2 = {4d 65 73 73 61 67 65 73 20 61 72 65 20 73 65 6e 74 3a 20 90 02 10 4f 66 66 6c 69 6e 65 2c 20 69 6e 63 72 65 61 73 65 20 74 69 6d 65 6f 75 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}