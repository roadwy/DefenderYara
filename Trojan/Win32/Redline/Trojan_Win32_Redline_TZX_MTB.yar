
rule Trojan_Win32_Redline_TZX_MTB{
	meta:
		description = "Trojan:Win32/Redline.TZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 54 2e 90 01 01 83 f0 90 01 01 81 c2 90 01 04 03 c7 c1 e2 90 01 01 8a 04 02 88 44 2e 90 01 01 8b c1 83 f8 90 01 01 7c 90 01 01 eb 90 01 01 8d 9b 90 01 04 0f b6 14 30 0f b6 4c 30 90 01 01 81 c2 90 01 04 c1 e2 90 01 01 03 cf 8a 0c 0a 88 0c 30 48 83 f8 90 01 01 7d 90 00 } //01 00 
		$a_01_1 = {7a 61 73 66 61 66 73 61 2e 65 78 65 } //00 00  zasfafsa.exe
	condition:
		any of ($a_*)
 
}