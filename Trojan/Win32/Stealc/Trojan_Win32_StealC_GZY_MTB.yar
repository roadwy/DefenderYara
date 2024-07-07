
rule Trojan_Win32_StealC_GZY_MTB{
	meta:
		description = "Trojan:Win32/StealC.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 33 89 45 90 01 01 8b 45 90 01 01 c1 e8 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 83 65 90 01 02 c7 05 90 01 04 ee 3d ea f4 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 33 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}