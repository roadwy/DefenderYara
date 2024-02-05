
rule Trojan_Win32_Glupteba_NJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f0 8d 0c 2b 33 90 02 03 33 90 02 03 2b 90 02 03 81 3d 90 02 08 90 18 81 90 02 05 83 90 02 07 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}