
rule Trojan_Win32_PSWStealer_XP_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.XP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d4 69 d2 ?? ?? ?? ?? 89 55 d4 c6 45 ?? 01 c6 45 ?? ?? c6 45 ?? 01 0f bf 45 9c 35 ?? ?? ?? ?? 66 89 45 9c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}