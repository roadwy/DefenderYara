
rule Trojan_Win32_Reline_RT_MTB{
	meta:
		description = "Trojan:Win32/Reline.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d f1 82 e0 be 75 ?? 0f b6 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 0f b6 00 88 45 ?? b8 b8 8b 14 bf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}