
rule Trojan_Win32_Zbot_RO_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 03 8d 90 01 02 ff ff 8b 55 0c 03 95 90 01 02 ff ff 8a 02 88 01 83 bd 90 01 02 ff ff 00 90 00 } //01 00 
		$a_01_1 = {32 34 67 4f 70 33 33 33 65 79 41 } //01 00  24gOp333eyA
		$a_01_2 = {76 6c 74 4d 46 6d 75 6c 54 41 61 6e 4d 65 65 57 31 } //00 00  vltMFmulTAanMeeW1
	condition:
		any of ($a_*)
 
}