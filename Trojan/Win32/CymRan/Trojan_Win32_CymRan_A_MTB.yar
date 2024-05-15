
rule Trojan_Win32_CymRan_A_MTB{
	meta:
		description = "Trojan:Win32/CymRan.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 0c 1a 8b c2 8b 5d 90 01 01 83 e0 90 01 01 42 8a 84 30 90 01 04 32 04 0b 8b 5d 90 01 01 88 01 3b d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}