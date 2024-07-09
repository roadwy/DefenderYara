
rule Trojan_Win32_Ursnif_RT_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af ca 85 c9 8b 54 24 ?? 03 d0 89 54 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 31 0a 83 c0 04 3b 44 24 ?? 7e ?? c7 44 24 ?? 04 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}