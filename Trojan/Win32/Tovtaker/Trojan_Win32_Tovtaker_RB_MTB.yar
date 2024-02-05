
rule Trojan_Win32_Tovtaker_RB_MTB{
	meta:
		description = "Trojan:Win32/Tovtaker.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 be 64 00 00 00 f7 fe 0f b6 54 15 90 01 01 33 ca 88 4d 90 01 01 66 0f be 45 90 01 01 0f b7 c8 51 8b 4d 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}