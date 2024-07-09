
rule Trojan_Win32_PSWStealer_XZ_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d8 31 d2 8d 4d ?? f7 75 ?? 8b 45 ?? 0f be 34 10 e8 ?? ?? ?? ?? 8d 4d ?? e8 ?? ?? ?? ?? 69 c6 ?? ?? ?? ?? 30 04 1f 43 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}