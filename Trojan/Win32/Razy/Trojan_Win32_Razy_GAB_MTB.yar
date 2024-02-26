
rule Trojan_Win32_Razy_GAB_MTB{
	meta:
		description = "Trojan:Win32/Razy.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 68 10 60 10 30 28 a8 90 01 04 b0 f8 a0 90 01 04 40 d0 38 a0 90 01 04 30 88 90 01 04 e0 90 01 01 88 d0 88 50 b0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}