
rule Trojan_Win32_PikaBot_CCFK_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 ?? 0f af 45 ?? 2b d0 03 55 ?? 03 55 ?? 2b 55 ?? 0f b6 54 15 ?? 33 ca 8b 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}