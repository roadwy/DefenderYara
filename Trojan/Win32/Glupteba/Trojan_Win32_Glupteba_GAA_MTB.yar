
rule Trojan_Win32_Glupteba_GAA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 11 81 c1 90 01 04 29 c7 81 c6 90 01 04 39 d9 90 01 02 c3 01 fe 29 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}