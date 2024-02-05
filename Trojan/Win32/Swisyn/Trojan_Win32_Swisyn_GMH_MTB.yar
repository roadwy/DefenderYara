
rule Trojan_Win32_Swisyn_GMH_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 b7 88 61 b8 90 01 04 03 c5 81 c0 93 00 00 00 b9 34 06 00 00 ba 90 01 04 30 10 40 49 90 00 } //01 00 
		$a_80_1 = {54 4a 70 72 6f 6a 4d 61 69 6e 2e 65 78 65 } //TJprojMain.exe  00 00 
	condition:
		any of ($a_*)
 
}