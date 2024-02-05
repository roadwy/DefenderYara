
rule Backdoor_WinNT_Rustock_gen_E{
	meta:
		description = "Backdoor:WinNT/Rustock.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_08_0 = {49 00 6d 00 61 00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 5c 00 3f 00 3f 00 5c 00 25 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 44 00 52 00 49 00 56 00 45 00 52 00 53 00 5c 00 25 00 77 00 73 00 25 00 63 00 2e 00 73 00 79 00 73 00 00 00 } //01 00 
		$a_03_1 = {ff 75 f4 ff 15 90 01 02 01 00 ff 75 f4 ff 15 90 01 02 01 00 8d 85 88 f6 ff ff 50 8d 45 e0 50 ff d6 8d 45 e0 50 e8 90 01 04 5f 5e b8 83 01 00 c0 5b c9 c2 08 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}