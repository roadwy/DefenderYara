
rule Trojan_Win32_PikaBot_CCFB_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 10 8b 45 90 01 01 03 45 90 01 01 2d 90 01 04 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 02 83 45 90 01 02 8b 45 90 01 01 3b 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}