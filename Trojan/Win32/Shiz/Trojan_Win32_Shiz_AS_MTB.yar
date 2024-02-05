
rule Trojan_Win32_Shiz_AS_MTB{
	meta:
		description = "Trojan:Win32/Shiz.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d1 29 15 f2 f0 41 00 d1 ca 2b 15 e0 f4 41 00 42 c1 c2 06 4a d1 ca 29 15 59 ff 41 00 89 1d d7 fc 41 00 8b 15 d7 fc 41 00 81 fa 1c 80 d3 81 } //00 00 
	condition:
		any of ($a_*)
 
}