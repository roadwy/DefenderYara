
rule Trojan_Win32_Remcos_ZG_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 10 c7 45 f8 00 00 00 00 e8 90 01 04 c7 45 f8 00 00 00 00 eb 09 8b 45 f8 83 c0 01 89 45 f8 81 7d f8 90 01 04 0f 83 90 00 } //1
		$a_02_1 = {68 3e 50 b3 93 68 90 01 04 ff 15 90 01 04 50 e8 90 01 04 83 c4 08 89 45 f4 8d 90 01 03 6a 40 68 90 01 04 68 90 01 04 ff 55 f4 8b 90 01 0a 83 c4 04 8b e5 5d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}