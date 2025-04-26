
rule Trojan_Win32_Staser_BB_MTB{
	meta:
		description = "Trojan:Win32/Staser.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8b 10 31 15 [0-04] c7 45 d8 01 00 00 00 eb 10 } //2
		$a_01_1 = {33 4a 01 bb d0 f6 46 00 3b c8 75 24 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}