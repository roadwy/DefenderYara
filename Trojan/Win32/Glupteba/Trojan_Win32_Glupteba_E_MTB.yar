
rule Trojan_Win32_Glupteba_E_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.E!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 33 45 f0 89 45 e4 8b 4d e4 33 4d ec 89 4d e4 8b 55 d0 2b 55 e4 89 55 d0 } //00 00 
	condition:
		any of ($a_*)
 
}