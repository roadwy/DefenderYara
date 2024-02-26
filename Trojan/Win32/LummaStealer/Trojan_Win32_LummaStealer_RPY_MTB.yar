
rule Trojan_Win32_LummaStealer_RPY_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d b4 8b f0 6a 00 8d 45 a0 c7 45 a0 00 00 00 00 50 8b 11 6a 01 51 ff 52 0c 85 c0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_LummaStealer_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 46 78 89 c4 50 83 ec 1c 89 e0 83 e0 f0 89 46 70 89 c4 50 83 ec 0c 89 e0 83 e0 f0 89 46 7c 89 c4 50 83 ec 1c 89 e0 83 e0 f0 89 86 80 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}