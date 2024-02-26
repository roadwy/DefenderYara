
rule Backdoor_Win64_Coroxy_ZD_MTB{
	meta:
		description = "Backdoor:Win64/Coroxy.ZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 90 01 01 31 18 83 45 90 01 02 83 45 90 01 02 8b 45 90 01 01 3b 45 90 01 01 72 90 0a 50 00 8b 45 90 01 01 8b 55 90 01 01 01 02 6a 00 e8 90 01 04 8b 5d 90 01 01 03 5d 90 01 01 03 5d 90 01 01 2b d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}