
rule Trojan_Win32_Sabsik_FG_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 f9 03 0f b6 15 90 01 04 c1 e2 05 0b ca 88 0d 90 01 04 0f b6 05 90 01 04 f7 d8 a2 90 01 04 0f b6 0d 90 01 04 2b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}