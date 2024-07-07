
rule Trojan_Win32_Amadey_GNI_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 d9 f7 09 81 44 24 90 01 01 ae 7f 68 1a 81 44 24 90 01 01 b6 a2 b2 20 81 44 24 90 01 01 e5 a1 5a 02 81 44 24 90 01 01 e8 c2 1a 07 b8 90 01 04 f7 64 24 90 01 01 8b 44 24 90 01 01 81 fe 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}