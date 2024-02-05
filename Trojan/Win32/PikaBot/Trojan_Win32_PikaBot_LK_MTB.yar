
rule Trojan_Win32_PikaBot_LK_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 1c 01 8b 86 90 01 03 00 ff 86 90 01 03 00 48 31 05 90 01 04 81 ff 90 01 04 0f 8c 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}