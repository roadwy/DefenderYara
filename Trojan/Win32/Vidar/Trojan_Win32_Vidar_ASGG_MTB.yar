
rule Trojan_Win32_Vidar_ASGG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 6a 00 e8 ?? ?? ?? ff 8b 5d ?? 81 c3 ?? ?? ?? 00 2b 5d ?? 2b d8 6a 00 e8 ?? ?? ?? ff 2b d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ff 83 45 ec 04 83 45 ?? 04 8b 45 ec 3b 45 ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}