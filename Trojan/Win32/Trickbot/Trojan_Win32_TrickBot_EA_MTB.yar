
rule Trojan_Win32_TrickBot_EA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 02 a1 90 01 04 0f af 05 90 01 04 2b d8 03 1d 90 01 04 8b 55 0c 8a 04 0a 32 c3 8b 4d fc 8b 11 8b 4d 0c 88 04 11 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}