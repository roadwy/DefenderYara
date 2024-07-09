
rule Trojan_Win32_Ursnif_YOH_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.YOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 c2 48 a6 00 00 52 8b 45 ?? 05 58 a6 00 00 50 6a 00 6a 00 8b 4d ?? 0f b7 91 ?? ?? ?? ?? 81 f2 e4 07 00 00 52 6a 00 6a 00 6a 00 8b 45 } //1
		$a_03_1 = {33 d2 f7 f1 8b 45 d8 0f be 8c 10 ?? ?? ?? ?? 8b 55 d8 8b 82 ?? ?? ?? ?? 03 c1 8b 4d d8 8b 91 ?? ?? ?? ?? 8b 4d d8 0f b6 94 11 ?? ?? ?? ?? 03 c2 33 d2 b9 00 01 00 00 f7 f1 8b 45 d8 89 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}