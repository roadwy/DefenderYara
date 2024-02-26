
rule Trojan_Win32_Virlock_ARA_MTB{
	meta:
		description = "Trojan:Win32/Virlock.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 e9 } //02 00 
		$a_01_1 = {88 07 90 46 47 49 90 83 f9 00 90 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}