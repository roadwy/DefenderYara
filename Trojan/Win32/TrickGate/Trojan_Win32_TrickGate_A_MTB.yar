
rule Trojan_Win32_TrickGate_A_MTB{
	meta:
		description = "Trojan:Win32/TrickGate.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {09 c8 0f b6 4d 90 01 01 31 c8 88 c2 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}