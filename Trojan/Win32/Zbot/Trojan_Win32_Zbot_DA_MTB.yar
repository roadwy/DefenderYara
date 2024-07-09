
rule Trojan_Win32_Zbot_DA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 84 c1 cf 17 0f b6 17 47 47 c1 c7 17 89 7d 84 b9 bb ea 54 3f 81 c1 05 16 ab c0 3b d1 0f 82 ?? ?? ?? ?? 2b d1 03 d2 8b 45 fc c1 c8 13 03 c2 03 c2 c1 c8 0d 89 45 fc 85 d2 75 c4 } //1
		$a_00_1 = {8b 0e 8b 45 b4 35 11 2f dd f5 03 f0 8b 16 c1 c2 1f 83 e2 15 03 ca 4b 89 0f b8 88 68 18 ec 05 7c 97 e7 13 03 f8 85 db 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}