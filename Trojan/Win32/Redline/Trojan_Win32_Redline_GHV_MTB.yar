
rule Trojan_Win32_Redline_GHV_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 45 b4 b4 1d 32 c8 c6 45 bb 00 32 e8 88 4d b6 b6 1e 88 6d b9 32 d0 } //0a 00 
		$a_01_1 = {8a 85 60 ff ff ff 30 84 0d 61 ff ff ff 41 83 f9 10 72 } //00 00 
	condition:
		any of ($a_*)
 
}