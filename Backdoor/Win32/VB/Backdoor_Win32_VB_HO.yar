
rule Backdoor_Win32_VB_HO{
	meta:
		description = "Backdoor:Win32/VB.HO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 00 00 00 53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 00 00 00 00 10 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 00 00 } //01 00 
		$a_03_1 = {fe 64 64 ff 93 00 3a 90 01 04 28 34 ff 02 00 f5 01 00 00 00 6c 70 ff f5 01 00 00 00 ae f5 02 00 00 00 b2 aa 6c 0c 00 4d 54 ff 08 40 04 24 ff 0a 09 00 10 00 04 24 ff fb ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}