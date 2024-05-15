
rule Trojan_Win32_Ekstak_GPL_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 ca 0a 00 69 33 b0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}