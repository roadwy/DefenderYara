
rule Trojan_Win32_Glupteba_EDV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EDV!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 45 f0 04 8a c3 02 c0 f6 da 2a d0 00 55 ff 81 7d f0 10 08 } //0a 00 
		$a_01_1 = {8a c1 02 45 e8 2c 38 88 45 ff } //00 00 
	condition:
		any of ($a_*)
 
}