
rule Trojan_Win32_Vidar_RD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 95 7c ec ff ff 2b c6 8d 34 11 8b f8 33 d2 8b c1 f7 f7 8b 45 0c 41 8a 14 02 8b 85 ?? ?? ?? ?? 32 14 30 88 16 3b cb 72 ca } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}