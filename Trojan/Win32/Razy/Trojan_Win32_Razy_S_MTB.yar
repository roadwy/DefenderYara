
rule Trojan_Win32_Razy_S_MTB{
	meta:
		description = "Trojan:Win32/Razy.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {03 fa 34 eb 5f 81 c3 90 01 04 81 fb f4 01 00 00 75 05 bb 90 01 04 01 f9 29 ff c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}