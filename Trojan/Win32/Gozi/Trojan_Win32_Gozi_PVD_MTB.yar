
rule Trojan_Win32_Gozi_PVD_MTB{
	meta:
		description = "Trojan:Win32/Gozi.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 28 0f af 05 90 01 04 8b 8c 24 a0 02 00 00 03 c5 a3 90 01 04 a1 90 01 04 88 1c 07 47 3b fe 7c 90 00 } //1
		$a_00_1 = {0f b7 45 c0 0f af 45 bc 2b c8 89 4d b8 8a 45 cc 32 c2 88 45 e7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}