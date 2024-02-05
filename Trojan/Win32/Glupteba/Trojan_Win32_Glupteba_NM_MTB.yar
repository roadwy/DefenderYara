
rule Trojan_Win32_Glupteba_NM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 74 24 10 33 f1 2b fe 81 3d 90 02 08 75 90 02 02 6a 00 6a 00 ff 15 90 02 04 8b 90 02 06 29 90 02 03 83 90 02 08 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}