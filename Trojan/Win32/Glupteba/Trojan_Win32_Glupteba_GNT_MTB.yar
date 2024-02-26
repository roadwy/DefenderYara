
rule Trojan_Win32_Glupteba_GNT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {31 1f 01 f1 81 c7 04 00 00 00 29 d6 21 f1 39 c7 } //00 00 
	condition:
		any of ($a_*)
 
}