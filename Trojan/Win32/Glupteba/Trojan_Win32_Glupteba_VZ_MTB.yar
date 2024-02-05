
rule Trojan_Win32_Glupteba_VZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 39 d2 74 01 ea 31 1e 81 c6 04 00 00 00 47 39 c6 75 ee 47 51 8b 0c 24 83 c4 04 } //00 00 
	condition:
		any of ($a_*)
 
}