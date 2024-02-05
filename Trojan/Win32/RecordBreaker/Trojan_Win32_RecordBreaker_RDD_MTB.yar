
rule Trojan_Win32_RecordBreaker_RDD_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 c1 e9 18 33 4d fc } //02 00 
		$a_03_1 = {03 ca 81 e1 90 01 04 8b 45 f8 0f b6 0c 08 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}