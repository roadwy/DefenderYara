
rule Trojan_Win32_Vidar_CAS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {f3 a4 81 f1 90 01 04 c1 c7 90 01 01 43 29 90 01 05 29 90 01 05 4f 87 d1 f7 d8 90 00 } //05 00 
		$a_03_1 = {f7 d8 87 d1 47 89 90 01 05 4b c1 cf 1d 81 90 01 05 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}