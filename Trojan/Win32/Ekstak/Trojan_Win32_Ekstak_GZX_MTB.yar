
rule Trojan_Win32_Ekstak_GZX_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 39 bd 33 00 bc 1e 30 00 00 be 90 01 04 ca fc 04 00 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}