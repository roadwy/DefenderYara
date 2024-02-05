
rule Trojan_Win32_CobaltStrike_WMB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.WMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 14 08 83 c0 04 8b 0d 90 01 04 8b 35 90 01 04 81 f1 90 01 04 09 0d 90 01 04 8b ce 2b 0d 90 01 04 01 0d 90 01 04 b9 90 01 04 2b 0d 90 01 04 8b 15 90 01 04 03 15 90 01 04 01 0d 90 01 04 89 15 90 01 04 3d 90 01 04 7c 90 00 } //01 00 
		$a_01_1 = {53 74 61 72 74 58 70 72 } //00 00 
	condition:
		any of ($a_*)
 
}