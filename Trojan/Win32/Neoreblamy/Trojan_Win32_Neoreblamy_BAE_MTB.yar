
rule Trojan_Win32_Neoreblamy_BAE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 fe 00 8a 45 fe 88 45 fc 0f b6 45 fd 0f b6 4d fc 23 c1 74 06 83 65 ec 00 eb 0d 0f b6 45 fd 0f b6 4d fc 0b c1 89 45 ec 8a 45 ec 88 45 fb 8b 45 f0 d1 e0 89 45 f0 0f b6 45 fb 0b 45 f0 89 45 f0 eb } //4
		$a_01_1 = {c6 45 ff 00 8a 45 ff 88 45 fd 33 c0 40 8b 4d f4 d3 e0 23 45 0c 74 06 c6 45 fe 01 eb } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}