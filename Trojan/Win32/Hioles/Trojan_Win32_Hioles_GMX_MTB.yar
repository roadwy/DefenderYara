
rule Trojan_Win32_Hioles_GMX_MTB{
	meta:
		description = "Trojan:Win32/Hioles.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {88 c2 80 e2 90 01 01 20 de 88 cc 80 e4 90 01 01 20 dd 08 f2 08 ec 30 e2 88 95 90 01 04 08 c8 34 ff 88 85 90 01 04 8a 85 90 01 04 8a 8d 90 01 04 8a 95 90 01 04 80 ca 00 20 d1 08 c8 a8 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}