
rule Trojan_Win32_Spy_RPM_MTB{
	meta:
		description = "Trojan:Win32/Spy.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 14 8b f2 8b c8 2b f0 8b d7 8a 1c 0e 32 5d 0c 88 19 41 4a 75 f4 } //00 00 
	condition:
		any of ($a_*)
 
}