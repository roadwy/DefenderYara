
rule Trojan_Win32_Emotet_DAH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff 15 90 01 04 6a 00 6a 00 ff 15 90 1b 00 6a 00 6a 00 ff 15 90 1b 00 6a 00 6a 00 ff 15 90 1b 00 6a 00 6a 00 ff 15 90 1b 00 6a 00 6a 00 ff 15 90 1b 00 6a 00 6a 00 ff 15 90 1b 00 8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 90 01 04 33 c1 8b 55 08 03 55 f0 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}