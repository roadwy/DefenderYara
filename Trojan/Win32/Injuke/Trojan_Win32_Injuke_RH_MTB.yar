
rule Trojan_Win32_Injuke_RH_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 04 33 83 ff 0f 75 12 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 46 3b f7 7c b9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}