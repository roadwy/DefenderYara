
rule Trojan_Win32_Cobaltstrike_EG_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 48 63 54 24 ?? 0f be 0c 10 8b 44 24 ?? 41 b9 ?? ?? ?? ?? 99 41 f7 f9 83 c2 ?? 31 d1 48 63 44 24 ?? 41 88 0c 00 8b 44 24 ?? 83 c0 01 89 44 24 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}