
rule Backdoor_Win32_Coroxy_ZA_MTB{
	meta:
		description = "Backdoor:Win32/Coroxy.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 1a 03 1d 90 01 04 2b d8 e8 90 01 04 03 d8 a1 90 01 04 89 18 e8 90 01 04 8b 1d 90 01 04 03 1d 90 01 04 81 eb 90 01 04 03 1d 90 01 04 2b d8 e8 90 01 04 03 d8 a1 90 01 04 31 18 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}