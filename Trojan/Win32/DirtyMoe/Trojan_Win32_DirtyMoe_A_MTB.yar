
rule Trojan_Win32_DirtyMoe_A_MTB{
	meta:
		description = "Trojan:Win32/DirtyMoe.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f be 01 99 b9 90 01 04 f7 f9 81 c2 90 01 04 8b 45 90 01 01 03 45 90 01 01 8a 08 32 ca 8b 55 90 01 01 03 55 90 01 01 88 0a 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}