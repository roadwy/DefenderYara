
rule Trojan_Win32_PSWStealer_VU_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 89 4d e8 c6 45 e6 01 0f bf 55 c8 81 f2 7f 46 00 00 66 89 55 c8 c6 45 bf 01 c6 45 ef 01 0f bf 45 e0 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}