
rule Trojan_Win32_Lokibot_DECC_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.DECC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 71 b5 02 00 00 00 bc 29 40 00 cc 29 40 00 00 00 00 00 79 4f ad 33 99 66 cf 11 b7 } //01 00 
		$a_81_1 = {61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lokibot_DECC_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.DECC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b ca d1 e8 c1 e1 07 46 0b c8 03 cf 03 d1 0f be 3e 8b c2 85 ff 75 e9 } //00 00 
	condition:
		any of ($a_*)
 
}