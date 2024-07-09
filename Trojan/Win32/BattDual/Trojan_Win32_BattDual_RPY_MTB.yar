
rule Trojan_Win32_BattDual_RPY_MTB{
	meta:
		description = "Trojan:Win32/BattDual.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 2b 4d e4 89 4d e0 8b 55 e0 83 c2 01 89 55 f0 6a 04 68 00 10 00 00 8b 45 f0 50 6a 00 8b 4d f4 51 ff 15 ?? ?? ?? ?? 89 45 e8 6a 00 8b 55 f0 52 8b 45 ec 50 8b 4d e8 51 8b 55 f4 52 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}