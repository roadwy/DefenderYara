
rule Trojan_Win32_PikaBot_LKC_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.LKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 44 0d b0 34 90 01 01 88 84 0d 90 01 02 ff ff 41 83 f9 0c 7c ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}