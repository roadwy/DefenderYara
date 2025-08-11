
rule Trojan_Win32_TimbreStealer_GTD_MTB{
	meta:
		description = "Trojan:Win32/TimbreStealer.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 f8 8d 5b ?? 8b 44 24 ?? 8a 4c 3c ?? 0f b6 d1 03 c2 0f b6 c0 89 44 24 ?? 0f b6 44 04 18 88 44 3c ?? 8b 44 24 ?? 88 4c 04 ?? 0f b6 44 3c ?? 03 c2 0f b6 c0 0f b6 44 04 ?? 32 44 2b ?? 88 43 ?? 83 ee } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}