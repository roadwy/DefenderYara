
rule Backdoor_Win64_Coroxy_ZB_MTB{
	meta:
		description = "Backdoor:Win64/Coroxy.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ac 48 39 7d 90 01 01 77 90 01 01 48 83 7d 90 01 02 74 90 01 01 48 8b 55 90 01 01 88 02 8a 07 30 02 48 ff 45 90 01 01 eb 90 01 01 30 07 48 ff c9 48 83 7d 90 01 02 75 90 01 01 48 83 7d 90 01 02 75 90 01 01 66 83 7f 90 00 } //01 00 
		$a_01_1 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 65 70 20 62 79 70 61 73 73 20 2d 66 69 6c 65 } //01 00  -WindowStyle Hidden -ep bypass -file
		$a_01_2 = {72 75 6e 64 6c 6c } //00 00  rundll
	condition:
		any of ($a_*)
 
}