
rule Trojan_Win32_PSWStealer_VX_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.VX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 32 21 c0 48 29 fb 81 e6 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 40 31 31 f7 d0 bf ?? ?? ?? ?? bf ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 4b 81 e8 ?? ?? ?? ?? 29 d8 42 89 f8 48 81 ef } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}