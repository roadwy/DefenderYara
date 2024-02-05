
rule Trojan_Win32_Glupteba_GW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {31 13 b8 68 cc 32 6c 81 c3 90 01 04 81 ef 42 70 96 e3 21 c0 39 f3 75 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}