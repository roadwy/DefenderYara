
rule Backdoor_Win32_CobaltStrike_MBK_MTB{
	meta:
		description = "Backdoor:Win32/CobaltStrike.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 0f b7 01 33 d2 66 2b 05 90 02 04 33 d2 66 f7 35 90 02 04 33 d2 88 06 33 d2 46 33 d2 43 33 d2 83 c1 02 33 d7 3b da 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}