
rule Trojan_Win32_PSWStealer_FV_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 95 4c ff ff ff 03 55 f4 89 95 ?? ?? ?? ?? 8b 45 f0 0f af 45 fc 89 45 a8 8b 4d 80 0f af 4d fc 89 8d ?? ?? ?? ?? 8b 55 f8 0f af 95 ?? ?? ?? ?? 89 55 c4 8b 45 f8 0f af 85 ?? ?? ?? ?? 89 85 e4 fe ff ff } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}