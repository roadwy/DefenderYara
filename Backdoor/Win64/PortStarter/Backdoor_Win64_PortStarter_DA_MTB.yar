
rule Backdoor_Win64_PortStarter_DA_MTB{
	meta:
		description = "Backdoor:Win64/PortStarter.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 c7 40 08 03 00 00 00 48 8d 0d 90 01 04 48 89 08 48 8d 0d 90 01 04 48 89 48 10 48 c7 40 28 03 00 00 00 48 8d 0d 90 01 04 48 89 48 20 48 8d 0d 90 01 04 48 89 48 30 48 c7 40 48 04 00 00 00 48 8d 0d 90 01 04 48 89 48 40 48 8d 0d 90 01 04 48 89 48 50 48 c7 40 68 09 00 00 00 48 8d 0d 90 01 04 48 89 48 60 48 8d 0d 90 01 04 48 89 48 70 48 c7 80 88 00 00 00 06 00 00 00 48 8d 0d 90 00 } //01 00 
		$a_01_1 = {5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74 } //01 00  _cgo_dummy_export
		$a_01_2 = {6d 61 69 6e 2e 64 6c 6c } //00 00  main.dll
	condition:
		any of ($a_*)
 
}