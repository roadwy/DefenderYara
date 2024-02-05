
rule Trojan_Win32_Qbot_PO_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f0 68 03 90 01 03 ff 15 90 01 04 03 f0 68 90 01 04 ff 15 90 01 04 03 f0 8b 45 08 8b 08 2b ce 8b 55 08 89 0a 5e 8b e5 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}