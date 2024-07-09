
rule Trojan_Win32_Vidar_ASGF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? c7 45 ?? ?? ?? 00 00 6a 00 e8 ?? ?? ?? ff 8b 55 ?? 81 c2 ?? ?? ?? 00 2b 55 ?? 2b d0 8b 45 ?? 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}