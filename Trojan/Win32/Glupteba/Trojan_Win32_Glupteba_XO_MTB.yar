
rule Trojan_Win32_Glupteba_XO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.XO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 ea 31 0f 81 ea 90 01 04 be 90 01 04 81 c7 90 01 04 09 d2 39 c7 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}