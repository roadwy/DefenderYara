
rule Backdoor_Win64_BruteRatel_MB_MTB{
	meta:
		description = "Backdoor:Win64/BruteRatel.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 b9 27 00 00 00 f7 f9 8b c2 48 98 48 8d 0d 90 01 04 0f be 04 01 8b 8c 24 80 00 00 00 33 c8 8b c1 48 63 4c 24 30 48 8b 54 24 70 88 04 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}