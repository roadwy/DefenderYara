
rule Trojan_Win32_Zbot_BE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2a c1 f6 6d fc 8a d8 8a c1 f6 ea 2a d8 02 1d 90 02 04 02 1d 90 02 04 80 eb 02 30 1c 31 39 3d 90 02 04 7e 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}