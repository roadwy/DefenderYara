
rule Trojan_Win32_Glupteba_RPO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {39 d2 74 01 ea 31 18 90 02 10 81 c0 04 00 00 00 39 d0 75 ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}