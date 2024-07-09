
rule Trojan_Win32_Ursnif_RB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 02 89 ?? 24 ?? 85 c9 74 1b 8b 10 2b 54 24 ?? 8b ?? 24 ?? 01 54 24 ?? 83 44 24 ?? ?? 83 c0 ?? 49 89 ?? 75 e5 8b 4e } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}