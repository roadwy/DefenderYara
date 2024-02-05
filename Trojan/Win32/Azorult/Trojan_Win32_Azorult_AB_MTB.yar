
rule Trojan_Win32_Azorult_AB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.AB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 49 40 0f 28 ca 0f 10 41 a0 66 0f ef c2 0f 11 41 a0 0f 10 41 b0 66 0f ef c8 0f 11 49 b0 0f 28 ca 0f 10 41 c0 66 0f ef c8 0f 11 49 c0 0f 10 41 d0 66 0f ef c2 0f 11 41 d0 83 ee 01 75 c2 } //00 00 
	condition:
		any of ($a_*)
 
}