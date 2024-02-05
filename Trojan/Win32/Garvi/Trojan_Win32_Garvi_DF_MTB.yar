
rule Trojan_Win32_Garvi_DF_MTB{
	meta:
		description = "Trojan:Win32/Garvi.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 03 8a 84 05 90 02 04 30 04 11 41 3b 8d e8 fd ff ff 72 90 00 } //01 00 
		$a_01_1 = {8a 18 0f b6 14 07 0f be cb 3b ca 75 5f 84 db 74 07 46 40 83 fe 08 72 } //00 00 
	condition:
		any of ($a_*)
 
}