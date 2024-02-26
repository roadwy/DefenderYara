
rule Trojan_Win32_Ekstak_GAE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 bf 90 01 04 42 65 00 00 be 0a 00 d4 bd 14 99 90 01 02 64 00 00 d4 00 00 dc d2 89 90 00 } //0a 00 
		$a_03_1 = {2a 01 00 00 00 a3 90 01 04 66 66 00 00 be 0a 00 d4 bd 14 99 96 20 66 00 00 d4 00 00 b4 79 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}