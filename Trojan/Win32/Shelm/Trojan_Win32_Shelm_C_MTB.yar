
rule Trojan_Win32_Shelm_C_MTB{
	meta:
		description = "Trojan:Win32/Shelm.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 3b 4d 0c 73 90 01 01 0f b6 55 10 8b 45 08 03 45 fc 0f b6 08 33 ca 8b 55 08 03 55 fc 88 0a eb 90 00 } //02 00 
		$a_01_1 = {50 51 52 4f 58 56 4f 50 52 50 4f 53 } //00 00  PQROXVOPRPOS
	condition:
		any of ($a_*)
 
}