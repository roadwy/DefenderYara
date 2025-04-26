
rule PWS_Win32_Zbot_TU{
	meta:
		description = "PWS:Win32/Zbot.TU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 55 f8 89 10 8b 45 0c 8b 55 f4 03 c2 89 45 f0 8b 07 03 45 f8 8b fe 99 f7 ff 8b 7d f0 8a 84 95 ?? ?? ?? ?? 30 07 ff 45 0c 8b 45 0c 3b 45 08 72 ?? 8b 45 f4 } //1
		$a_02_1 = {0f b7 48 06 3b d9 7c ?? 8d 85 ?? ?? ?? ?? 50 ff 75 d8 ff 55 cc a1 ?? ?? ?? ?? 8b 48 34 03 48 28 8d 85 ?? ?? ?? ?? 50 ff 75 d8 89 8d ?? ?? ?? ?? ff 55 f0 ff 75 d8 ff 55 e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}