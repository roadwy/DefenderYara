
rule Trojan_Win32_PikaBot_CCCB_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 48 50 8b 88 90 01 04 2b 48 10 01 0d 90 01 04 b9 90 01 04 8b 50 40 33 90 90 90 01 04 2b ca 01 88 90 01 04 8b 15 90 01 04 8b 0d 90 01 04 01 8a 90 01 04 81 ff 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}