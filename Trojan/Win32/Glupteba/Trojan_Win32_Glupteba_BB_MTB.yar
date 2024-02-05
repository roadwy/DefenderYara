
rule Trojan_Win32_Glupteba_BB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {39 ff 74 01 ea 31 0b b8 56 a1 bb bc 81 c3 04 00 00 00 39 d3 75 ea } //02 00 
		$a_01_1 = {39 ff 74 01 ea 31 01 81 c1 04 00 00 00 81 eb 76 5b 1f c4 46 39 d1 75 e8 } //00 00 
	condition:
		any of ($a_*)
 
}