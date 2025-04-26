
rule Trojan_Win32_Reline_RWB_MTB{
	meta:
		description = "Trojan:Win32/Reline.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 93 2d f1 eb 0f [0-05] 8b 45 [0-04] b9 f8 8c b7 88 88 45 ?? 0f b6 45 ?? 89 [0-05] 8b [0-05] 83 [0-05] 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}