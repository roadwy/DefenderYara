
rule Trojan_Win32_Glupteba_GY_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {21 f8 31 16 29 c0 b8 90 01 04 46 21 c0 39 ce 75 dd 89 c7 89 f8 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}