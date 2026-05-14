
rule Trojan_Win32_Lazy_ARL_MTB{
	meta:
		description = "Trojan:Win32/Lazy.ARL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 02 33 c8 8b 02 8d 96 ?? ?? ?? ?? 89 4c 24 ?? 0f b6 08 8b 44 24 ?? 03 c1 83 3a ?? 89 44 24 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}