
rule Trojan_Win32_Convagent_MKV_MTB{
	meta:
		description = "Trojan:Win32/Convagent.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 d8 88 45 90 01 01 0f b6 4d 90 01 01 83 e9 4d 88 90 01 01 df 0f b6 55 90 01 01 83 f2 50 88 55 90 01 01 0f b6 45 df 83 e8 4e 88 45 df 0f b6 4d df f7 d9 88 4d 90 01 01 0f b6 55 90 00 } //01 00 
		$a_03_1 = {f7 d8 88 45 90 01 01 0f b6 4d 90 01 01 81 f1 90 01 04 88 4d df 0f b6 55 90 01 01 81 c2 90 01 04 88 55 df 0f b6 45 90 01 01 83 f0 2b 88 45 90 01 01 0f b6 4d 90 01 01 83 e9 01 88 4d 90 01 01 8b 55 e0 8a 45 90 01 01 88 44 15 e4 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}