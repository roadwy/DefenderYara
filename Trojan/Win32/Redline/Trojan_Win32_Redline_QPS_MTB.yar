
rule Trojan_Win32_Redline_QPS_MTB{
	meta:
		description = "Trojan:Win32/Redline.QPS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 c7 05 c4 1d b9 02 fc 03 cf ff e8 f7 f8 ff ff 8b 45 0c 33 45 08 83 25 c4 1d b9 02 00 2b d8 89 45 0c 8b c3 c1 e0 04 } //01 00 
		$a_01_1 = {31 08 83 c5 70 c9 c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}