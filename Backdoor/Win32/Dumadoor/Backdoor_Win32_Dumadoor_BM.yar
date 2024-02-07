
rule Backdoor_Win32_Dumadoor_BM{
	meta:
		description = "Backdoor:Win32/Dumadoor.BM,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 64 76 70 2e 6c 6f 67 } //01 00  \dvp.log
		$a_00_1 = {5c 53 59 53 54 45 4d 33 32 5c 44 52 49 56 45 52 53 5c 45 54 43 5c 68 6f 73 74 73 } //01 00  \SYSTEM32\DRIVERS\ETC\hosts
		$a_00_2 = {61 80 38 6c 75 29 80 78 01 6f 75 23 80 78 02 67 75 1d 80 78 03 64 75 17 80 78 04 61 75 11 80 78 05 74 75 0b 80 78 06 61 75 05 } //05 00 
		$a_02_3 = {83 c6 0a ac 3c 2f 75 2e 83 c1 02 89 0d 90 01 04 c6 46 ff 00 68 90 01 04 68 90 01 04 e8 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 04 6a 01 59 e2 cb 68 90 01 04 6a 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}