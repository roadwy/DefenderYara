
rule Trojan_Win32_Fauppod_BH_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c2 83 ea ?? b8 ?? ?? ?? ?? 31 d2 89 15 ?? ?? ?? ?? 01 25 ?? ?? ?? ?? 31 d0 31 c2 29 c2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}