
rule Trojan_Win32_Glupteba_XG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.XG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 fb 39 c6 90 01 02 68 90 01 04 59 09 ff c3 90 0a 27 00 31 16 b9 90 01 04 81 c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}