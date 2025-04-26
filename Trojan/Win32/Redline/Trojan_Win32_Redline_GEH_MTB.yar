
rule Trojan_Win32_Redline_GEH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 3c 3e 8b c6 83 e0 ?? 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 2a df 00 1c 3e 46 59 3b f5 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}