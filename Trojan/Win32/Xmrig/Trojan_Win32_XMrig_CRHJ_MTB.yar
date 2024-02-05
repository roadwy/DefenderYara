
rule Trojan_Win32_XMrig_CRHJ_MTB{
	meta:
		description = "Trojan:Win32/XMrig.CRHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 45 d3 0f b6 4d d3 51 8d 4d e4 e8 90 01 04 0f b6 10 69 d2 90 01 04 83 e2 90 01 01 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}