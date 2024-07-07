
rule Trojan_Win32_Smokeloader_GME_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 90 01 01 03 54 24 90 01 01 03 cd 33 d1 8b 4c 24 90 01 01 03 c8 33 d1 2b fa 8b d7 c1 e2 90 01 01 81 3d 90 01 08 c7 05 90 01 08 89 54 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}