
rule TrojanSpy_Win32_Bancos_AMI{
	meta:
		description = "TrojanSpy:Win32/Bancos.AMI,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 66 00 6f 00 72 00 6d 00 65 00 20 00 73 00 75 00 61 00 20 00 73 00 65 00 6e 00 68 00 61 00 20 00 65 00 6c 00 65 00 74 00 72 00 6f 00 6e 00 69 00 63 00 61 00 20 00 63 00 6f 00 72 00 72 00 65 00 74 00 61 00 6d 00 65 00 6e 00 74 00 65 00 } //01 00 
		$a_01_1 = {66 00 2d 00 62 00 65 00 69 00 72 00 61 00 2d 00 73 00 69 00 6c 00 76 00 61 00 40 00 62 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00 
		$a_01_2 = {78 00 75 00 70 00 6f 00 31 00 39 00 53 00 41 00 } //01 00 
		$a_01_3 = {66 00 2d 00 61 00 74 00 61 00 6e 00 61 00 73 00 69 00 6f 00 2d 00 66 00 69 00 6c 00 68 00 6f 00 40 00 75 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00 
		$a_01_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 48 00 6f 00 73 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}