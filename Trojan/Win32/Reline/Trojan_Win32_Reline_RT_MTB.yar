
rule Trojan_Win32_Reline_RT_MTB{
	meta:
		description = "Trojan:Win32/Reline.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d f1 82 e0 be 75 90 01 01 0f b6 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 0f b6 00 88 45 90 01 01 b8 b8 8b 14 bf 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}