
rule Trojan_Win32_Zbot_BH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b f0 89 35 [0-04] 8b 55 d8 8b 45 e8 33 c2 89 45 d8 8b 5d fc 8b 45 d8 2b d8 89 5d d8 3b f0 0f 85 } //1
		$a_03_1 = {23 c7 89 05 [0-04] 8b 1d [0-04] 33 df 89 1d [0-04] 8b 3d [0-04] 47 4f 89 3d [0-04] e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}