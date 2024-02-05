
rule Backdoor_Win32_Poison_gen_C{
	meta:
		description = "Backdoor:Win32/Poison.gen!C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {04 08 00 73 74 75 62 50 61 74 68 18 04 28 00 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c } //01 00 
		$a_01_1 = {fa 0a 05 00 6b 69 6c 65 72 90 01 0d 00 09 31 32 37 2e 30 2e 30 2e 31 00 84 0d 8c 01 04 00 00 00 } //01 00 
		$a_01_2 = {00 00 e8 08 00 00 00 61 64 76 70 61 63 6b 00 ff 95 21 f1 ff ff 68 6b 37 04 7e 50 6a 00 e8 5e f5 } //00 00 
	condition:
		any of ($a_*)
 
}