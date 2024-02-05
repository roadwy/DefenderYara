
rule Trojan_Win32_Glupteba_FBX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.FBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 df b8 d8 85 40 00 09 ff e8 90 01 04 09 fb 31 01 81 c1 01 00 00 00 39 d1 75 e6 09 db c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}