
rule Trojan_Win32_Reline_RWB_MTB{
	meta:
		description = "Trojan:Win32/Reline.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 93 2d f1 eb 0f 90 02 05 8b 45 90 02 04 b9 f8 8c b7 88 88 45 90 01 01 0f b6 45 90 01 01 89 90 02 05 8b 90 02 05 83 90 02 05 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}