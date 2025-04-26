
rule Trojan_Win32_Vidar_BS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 8b 4d ?? c7 04 24 ?? ?? ?? ?? 8a 04 02 32 04 19 88 03 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}