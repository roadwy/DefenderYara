
rule Backdoor_Win32_Farfli_BM_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 55 8c 83 c2 01 89 55 8c 8b 45 8c 3b 45 dc 7d 16 8b 4d 08 03 4d 8c 0f be 11 83 f2 62 8b 45 a0 03 45 8c 88 10 eb } //01 00 
		$a_01_1 = {5b 50 52 49 4e 54 5f 53 43 52 45 45 4e 5d } //01 00 
		$a_01_2 = {5b 45 58 45 43 55 54 45 5f 6b 65 79 5d } //00 00 
	condition:
		any of ($a_*)
 
}