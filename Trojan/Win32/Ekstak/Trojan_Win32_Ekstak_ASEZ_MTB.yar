
rule Trojan_Win32_Ekstak_ASEZ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 3f 12 44 00 90 01 01 71 40 00 00 c4 0a 00 1a 83 6e 90 01 01 4d 29 40 00 00 d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}