
rule Trojan_Win32_Dridex_MX_MTB{
	meta:
		description = "Trojan:Win32/Dridex.MX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 5c 00 54 00 45 00 53 00 54 00 41 00 50 00 50 00 2e 00 45 00 58 00 45 00 00 00 50 00 50 00 2e 00 45 00 58 00 45 00 00 00 54 00 41 00 50 00 50 00 2e 00 45 00 58 00 45 00 } //03 00 
		$a_01_1 = {43 3a 5c 5c 54 45 53 54 41 50 50 2e 45 58 45 00 50 50 2e 45 58 45 00 54 41 50 50 2e 45 58 45 00 } //02 00 
		$a_01_2 = {73 65 6c 66 2e 45 58 45 } //02 00 
		$a_01_3 = {73 00 65 00 6c 00 66 00 2e 00 45 00 58 00 45 00 } //00 00 
	condition:
		any of ($a_*)
 
}