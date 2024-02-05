
rule TrojanDropper_Win32_VB_EK{
	meta:
		description = "TrojanDropper:Win32/VB.EK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 00 00 00 57 69 6e 45 78 65 63 00 90 01 94 0c 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 90 00 } //01 00 
		$a_01_1 = {fe 64 64 ff 93 00 3a 14 ff 11 00 28 34 ff 02 00 f5 01 00 00 00 6c 70 ff f5 01 00 00 00 ae f5 02 00 00 00 b2 aa 6c 0c 00 4d 54 ff 08 40 04 24 ff 0a 12 00 10 00 04 24 ff fb ef } //00 00 
	condition:
		any of ($a_*)
 
}