
rule Trojan_Win32_PSWStealer_XB_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.XB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 cb b8 d8 85 40 00 29 d9 e8 ?? ?? ?? ?? 31 06 81 c6 ?? ?? ?? ?? 39 d6 75 e8 01 cb c3 81 eb ?? ?? ?? ?? 01 d9 8d 04 38 01 cb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}