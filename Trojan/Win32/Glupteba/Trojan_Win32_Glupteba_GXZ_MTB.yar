
rule Trojan_Win32_Glupteba_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {29 c0 31 1a 40 42 39 fa 75 90 01 01 48 81 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}