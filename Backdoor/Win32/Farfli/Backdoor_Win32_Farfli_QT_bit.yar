
rule Backdoor_Win32_Farfli_QT_bit{
	meta:
		description = "Backdoor:Win32/Farfli.QT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 79 62 2f 6c 6f 67 2e 68 74 6d 6c 3f } //01 00 
		$a_01_1 = {33 36 30 53 61 66 65 2e 65 78 65 } //01 00 
		$a_01_2 = {5c 46 6f 6e 74 73 5c 73 65 72 76 69 63 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}