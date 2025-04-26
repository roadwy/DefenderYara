
rule Trojan_Win32_Vidar_GFG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f4 8b 45 08 01 d0 0f b6 18 8b 55 f4 8b 45 f0 01 d0 0f b6 08 8b 55 f4 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f4 01 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}