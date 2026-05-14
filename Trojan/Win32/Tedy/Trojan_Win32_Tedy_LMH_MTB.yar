
rule Trojan_Win32_Tedy_LMH_MTB{
	meta:
		description = "Trojan:Win32/Tedy.LMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 14 0f b6 04 06 8b 57 08 8d 3c 11 99 bb c8 01 00 00 f7 fb b8 ?? ?? ?? ?? 46 80 c2 36 30 17 f7 e1 c1 ea 03 8d 14 92 03 d2 8b c1 2b c2 f7 d8 1b c0 23 f0 8b 45 0c 41 3b c8 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}