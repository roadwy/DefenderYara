
rule Trojan_Win32_Vidar_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 31 18 83 45 ?? ?? 6a 00 e8 ?? ?? ?? ?? 83 c0 ?? 01 45 ?? 8b 45 ?? 3b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}