
rule Trojan_Win32_Zenpak_ASW_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 03 6b c2 ?? 8b 8c ?? ?? ?? 00 00 29 c1 89 c8 83 e8 ?? 89 ?? 24 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}