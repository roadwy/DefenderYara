
rule Trojan_Win32_Convagent_MKV_MTB{
	meta:
		description = "Trojan:Win32/Convagent.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 d8 88 45 ?? 0f b6 4d ?? 83 e9 4d 88 ?? df 0f b6 55 ?? 83 f2 50 88 55 ?? 0f b6 45 df 83 e8 4e 88 45 df 0f b6 4d df f7 d9 88 4d ?? 0f b6 55 } //1
		$a_03_1 = {f7 d8 88 45 ?? 0f b6 4d ?? 81 f1 ?? ?? ?? ?? 88 4d df 0f b6 55 ?? 81 c2 ?? ?? ?? ?? 88 55 df 0f b6 45 ?? 83 f0 2b 88 45 ?? 0f b6 4d ?? 83 e9 01 88 4d ?? 8b 55 e0 8a 45 ?? 88 44 15 e4 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}