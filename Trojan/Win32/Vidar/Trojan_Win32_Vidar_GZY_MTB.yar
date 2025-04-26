
rule Trojan_Win32_Vidar_GZY_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 03 df ff d6 8b c8 33 d2 8b c7 f7 f1 8b 45 ?? 68 ?? ?? ?? ?? 8a 0c 02 8b 55 ?? 32 0c 1a 88 0b ff d6 68 ?? ?? ?? ?? ff d6 8b 5d ?? 47 3b 7d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}