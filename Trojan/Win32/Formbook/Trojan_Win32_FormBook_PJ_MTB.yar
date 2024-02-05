
rule Trojan_Win32_FormBook_PJ_MTB{
	meta:
		description = "Trojan:Win32/FormBook.PJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 06 46 85 c0 74 28 bb 00 00 00 00 53 31 14 e4 5a 6a 08 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 57 83 e7 00 31 df 83 e0 00 31 f8 5f aa 49 75 cc } //01 00 
		$a_01_1 = {0f b6 06 46 85 c0 74 24 bb 00 00 00 00 53 31 14 e4 5a 6a 08 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 53 8f 45 f8 ff 75 f8 58 aa 49 75 d0 } //00 00 
	condition:
		any of ($a_*)
 
}