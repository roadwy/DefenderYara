
rule Trojan_Win32_HeavensGate_RPY_MTB{
	meta:
		description = "Trojan:Win32/HeavensGate.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 48 83 ec 28 0f 05 48 8b 4d b8 48 8d 64 cc 28 5f 48 89 45 b0 e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb } //00 00 
	condition:
		any of ($a_*)
 
}