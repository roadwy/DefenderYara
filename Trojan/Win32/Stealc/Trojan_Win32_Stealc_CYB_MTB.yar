
rule Trojan_Win32_Stealc_CYB_MTB{
	meta:
		description = "Trojan:Win32/Stealc.CYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {b8 31 a2 00 00 01 85 a0 e2 ff ff a1 f4 90 01 01 43 00 03 85 a4 e2 ff ff 8b 8d a0 e2 ff ff 03 8d a4 e2 ff ff 8a 09 88 08 81 3d 90 01 04 ab 05 00 00 75 90 00 } //02 00 
		$a_01_1 = {30 01 83 fb 0f 75 19 } //00 00 
	condition:
		any of ($a_*)
 
}