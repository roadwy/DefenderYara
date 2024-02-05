
rule Trojan_Win32_Glupteba_EA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 8b 45 f4 8b d3 d3 ea 03 c3 03 55 d8 33 d0 31 55 f8 2b 7d f8 } //00 00 
	condition:
		any of ($a_*)
 
}