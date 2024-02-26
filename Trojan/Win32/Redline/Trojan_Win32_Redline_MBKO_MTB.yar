
rule Trojan_Win32_Redline_MBKO_MTB{
	meta:
		description = "Trojan:Win32/Redline.MBKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 80 34 1e 90 01 01 68 90 01 04 68 90 01 04 e8 90 01 04 50 e8 90 01 03 ff 80 04 1e 90 01 01 68 90 01 04 68 90 01 04 e8 90 01 03 ff 50 e8 90 01 03 ff fe 0c 1e 83 c4 30 46 3b f7 0f 82 90 00 } //01 00 
		$a_01_1 = {50 72 6f 74 6f 63 6f 6c 20 6f 66 20 4d 69 6e 64 } //00 00  Protocol of Mind
	condition:
		any of ($a_*)
 
}