
rule Backdoor_Win32_Floodnet_C{
	meta:
		description = "Backdoor:Win32/Floodnet.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 30 05 8a 08 88 0c 02 40 4e 75 f4 } //01 00 
		$a_01_1 = {c6 85 d5 fc ff ff 59 c6 85 d6 fc ff ff 53 c6 85 d7 fc ff ff 54 c6 85 d8 fc ff ff 45 c6 85 d9 fc ff ff 4d } //01 00 
		$a_01_2 = {8d 04 40 33 d2 f7 74 24 04 8b c2 } //01 00 
		$a_01_3 = {69 6e 20 55 64 70 50 61 63 6b 46 6c 6f 6f 64 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}