
rule Trojan_Win32_RacoonStealer_RPC_MTB{
	meta:
		description = "Trojan:Win32/RacoonStealer.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72 e3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}