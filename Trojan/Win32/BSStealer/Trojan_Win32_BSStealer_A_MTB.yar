
rule Trojan_Win32_BSStealer_A_MTB{
	meta:
		description = "Trojan:Win32/BSStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f be c0 33 c3 69 d8 90 01 04 8a 01 41 84 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}