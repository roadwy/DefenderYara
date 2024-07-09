
rule Trojan_Win32_HyperBro_GXZ_MTB{
	meta:
		description = "Trojan:Win32/HyperBro.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 83 c0 01 89 45 f4 8b 4d f4 3b 4d f8 ?? ?? 8b 55 ec 03 55 f4 0f b6 02 33 45 e4 8b 4d ec 03 4d f4 88 01 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}