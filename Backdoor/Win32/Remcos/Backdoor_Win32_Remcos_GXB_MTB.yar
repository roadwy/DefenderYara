
rule Backdoor_Win32_Remcos_GXB_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.GXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {66 0f ef c1 0f 11 80 90 01 04 0f 10 80 90 01 04 66 0f ef c1 0f 11 80 90 01 04 0f 10 80 90 01 04 66 0f ef c1 0f 11 80 90 01 04 0f 10 80 90 01 04 66 0f ef c1 0f 11 80 90 01 04 83 c0 40 3d 00 a4 08 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}