
rule Trojan_Win32_Ursnif_BAA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 31 0f af f8 8d 50 ?? 89 15 ?? ?? ?? ?? 8d 50 ?? 81 c6 ?? ?? ?? ?? 2b c2 8d 84 00 ?? ?? ?? ?? 89 31 2b fa 83 c1 04 83 eb 01 a3 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}