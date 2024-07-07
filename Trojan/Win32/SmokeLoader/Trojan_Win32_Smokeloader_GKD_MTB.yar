
rule Trojan_Win32_Smokeloader_GKD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c7 31 45 90 01 01 89 35 90 01 04 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //10
		$a_03_1 = {8b ec 51 51 68 90 01 04 ff 35 90 01 04 c6 05 90 01 04 56 c6 05 90 01 04 69 c6 05 90 01 04 72 c6 05 90 01 04 50 c6 05 90 01 04 74 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}