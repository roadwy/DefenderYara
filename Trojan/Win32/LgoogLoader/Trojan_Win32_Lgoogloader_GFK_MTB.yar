
rule Trojan_Win32_Lgoogloader_GFK_MTB{
	meta:
		description = "Trojan:Win32/Lgoogloader.GFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {2a d1 8b 85 90 01 04 8a 85 90 01 04 02 05 90 01 04 32 c2 a2 90 01 04 8a 45 9c 0f be f0 90 00 } //10
		$a_01_1 = {66 33 c1 8b 4d a8 0f b7 d0 8b 45 ac 66 2b d1 66 8b 4d b8 0f b7 c9 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}