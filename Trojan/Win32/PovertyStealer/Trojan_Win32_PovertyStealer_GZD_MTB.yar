
rule Trojan_Win32_PovertyStealer_GZD_MTB{
	meta:
		description = "Trojan:Win32/PovertyStealer.GZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b 4d fc 8a 94 4d ?? ?? ?? ?? 88 54 05 bc 8b 45 fc 0f be 4c 05 bc 83 f9 2c ?? ?? 8b 55 fc c6 44 15 bc 2e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}