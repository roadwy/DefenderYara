
rule Trojan_Win32_Reline_RM_MTB{
	meta:
		description = "Trojan:Win32/Reline.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 08 8b 5d 90 01 01 8b 7d 90 01 01 8b 75 90 01 01 b8 47 68 9c a9 89 5d 90 01 01 81 c3 b0 00 00 00 3d 47 68 9c a9 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}