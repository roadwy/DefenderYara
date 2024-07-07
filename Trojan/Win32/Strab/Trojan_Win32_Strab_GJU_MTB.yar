
rule Trojan_Win32_Strab_GJU_MTB{
	meta:
		description = "Trojan:Win32/Strab.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 3d 90 01 04 03 ca 0f b6 c1 8b 4d 08 8a 84 05 90 01 04 30 04 0e 46 3b 75 0c 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}