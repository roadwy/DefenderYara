
rule Trojan_Win32_Rhadamanthys_JJH_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.JJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea ?? 03 54 24 ?? 03 fe 31 7c 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 4d 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}