
rule Trojan_Win32_Injuke_RJ_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 03 f0 03 eb 33 f5 33 74 24 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}