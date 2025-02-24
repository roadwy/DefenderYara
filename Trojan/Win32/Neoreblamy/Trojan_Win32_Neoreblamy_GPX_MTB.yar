
rule Trojan_Win32_Neoreblamy_GPX_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 0c 73 3b 8b 45 10 03 45 fc 33 d2 f7 35 ?? ?? ?? ?? 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}