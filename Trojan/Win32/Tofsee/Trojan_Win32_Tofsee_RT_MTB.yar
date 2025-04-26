
rule Trojan_Win32_Tofsee_RT_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 54 24 ?? 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 44 24 ?? 8d 0c 37 33 c1 31 44 24 ?? 83 3d ?? ?? ?? ?? 42 c7 05 ?? ?? ?? ?? 36 06 ea e9 89 44 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}