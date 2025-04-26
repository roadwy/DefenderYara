
rule Trojan_Win32_Fauppod_MH_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 e5 83 ec 04 89 3c 24 51 83 c4 04 56 52 83 c4 04 89 4c 24 fc 83 ec 04 68 ?? ?? ?? ?? 83 c4 04 52 83 c4 04 8b 7d 08 53 83 c4 04 8b 75 0c 89 c0 8b 4d 10 85 c9 74 } //2
		$a_03_1 = {83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 8b 7d 0c 52 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 57 5a 31 c0 66 8b 06 46 46 53 83 c4 04 50 83 c4 04 85 c0 74 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}