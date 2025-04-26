
rule Trojan_Win32_PikaBot_CCFB_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 10 8b 45 ?? 03 45 ?? 2d ?? ?? ?? ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}