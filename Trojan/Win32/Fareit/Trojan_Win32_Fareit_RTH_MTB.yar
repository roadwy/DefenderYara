
rule Trojan_Win32_Fareit_RTH_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 33 d2 52 50 8b 45 ?? 8b 40 ?? 99 03 04 24 13 54 24 ?? 83 c4 08 } //1
		$a_03_1 = {8b 07 8b 00 25 ff ff 00 00 50 56 e8 ?? ?? ?? ?? 8b 17 89 02 eb ?? 8b 45 ?? 83 c0 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}