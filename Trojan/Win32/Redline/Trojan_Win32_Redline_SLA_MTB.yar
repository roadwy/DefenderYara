
rule Trojan_Win32_Redline_SLA_MTB{
	meta:
		description = "Trojan:Win32/Redline.SLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f b6 d1 d0 c9 f6 de 81 fd 90 01 04 32 d9 89 04 0c 8d ad 90 01 04 8b 54 25 90 01 01 66 90 01 02 33 d3 f7 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}