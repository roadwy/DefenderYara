
rule Trojan_Win32_Cutwail_GBY_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.GBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 cb 01 fb 8b 7d e8 89 4d c8 8a 0c 0f 0f b6 f9 88 4d c7 8b 4d d0 01 cf 8b 4d ec 0f b6 14 11 01 d7 81 f6 ?? ?? ?? ?? 89 f8 99 f7 fe 8b 75 e8 8a 0c 16 8b 7d c8 88 0c 3e 8a 4d c7 88 0c 16 8b 4d cc 81 c1 ?? ?? ?? ?? 39 cb 89 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}