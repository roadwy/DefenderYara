
rule Trojan_Win32_PikaBot_CCFJ_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 01 8b 85 ?? fe ff ff 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 54 15 ?? 33 ca 8b 85 ?? fe ff ff 2b 85 ?? ff ff ff 03 85 ?? ff ff ff 8b 95 ?? ff ff ff 88 0c 02 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}