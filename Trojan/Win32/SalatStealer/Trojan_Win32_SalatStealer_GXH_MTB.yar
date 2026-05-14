
rule Trojan_Win32_SalatStealer_GXH_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.GXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af fa f7 e2 01 ca 8b 4c 24 ?? 01 fa 8b 7c 24 ?? 29 d8 89 c6 89 44 24 ?? 19 fa 0f a4 d6 ?? 89 54 24 ?? 0f a4 c2 ?? 8b 44 24 ?? 01 c2 11 ce 31 d3 ba ?? ?? ?? ?? 31 f7 01 d8 89 5c 24 ?? 8b 5c 24 ?? 89 c6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}