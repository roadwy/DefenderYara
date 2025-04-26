
rule Trojan_Win32_Vidar_PAX_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 55 94 8d 94 95 ?? ?? ?? ?? 8b 1a 89 18 89 0a 8b 00 03 c1 25 ?? ?? ?? ?? 79 ?? 48 [0-0a] 0f b6 d1 8d 84 85 98 03 00 00 39 10 75 08 8b 45 8c 88 0c 30 eb 0a 8a 00 32 c1 8b 4d 8c 88 04 31 ff 75 88 ff 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}