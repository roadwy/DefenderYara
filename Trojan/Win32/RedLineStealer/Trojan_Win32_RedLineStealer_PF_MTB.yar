
rule Trojan_Win32_RedLineStealer_PF_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d f8 3b c2 0f b6 3f c1 e6 ?? c1 e0 ?? 0b f7 ff 45 f8 66 c1 c7 ?? 23 fc 0f b7 3c 0a 0f b7 cf 2b d5 66 0f ba fa a3 8b d0 f8 c1 ea } //1
		$a_03_1 = {8b 6c 25 fc 66 c1 e6 ?? 66 8b df 66 23 df 89 44 25 00 8b f5 5b 5f f7 c3 ?? ?? ?? ?? 66 0f bc c2 5d 66 c1 e8 ?? 66 25 ?? ?? 8d ad fc ff ff ff 0f b7 c3 66 0f bd c4 8b 44 25 00 33 c3 66 85 f9 8d 80 a2 0a 16 1f 85 ea f9 0f c8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}