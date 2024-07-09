
rule Trojan_Win32_Emotet_KPV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.KPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 8a 8c 15 ?? ?? ff ff 30 08 40 ff 4d f8 89 45 08 0f 85 } //2
		$a_02_1 = {8a 08 32 8c 15 ?? ?? ff ff 8b 55 10 03 95 ?? ?? ff ff 88 0a 8b 85 ?? ?? ff ff 83 c0 01 89 85 } //2
		$a_00_2 = {8a 45 d0 83 65 e4 00 22 c2 08 45 cb 8a 45 ca 88 04 3e } //2
		$a_00_3 = {8b 44 24 14 83 c0 01 89 44 24 14 0f b6 54 14 18 30 50 ff 83 bc 24 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}