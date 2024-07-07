
rule Trojan_Win32_PikaBot_CCFD_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b ca 8b 85 90 01 04 0f b6 0c 08 8b 85 90 01 04 33 d2 be 90 01 04 f7 f6 0f b6 54 15 90 01 01 33 ca 8b 85 90 01 04 2b 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}