
rule Trojan_Win32_Tedy_SXD_MTB{
	meta:
		description = "Trojan:Win32/Tedy.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 55 ec 52 68 ?? ?? ?? ?? 8d 85 ec fb ff ff 50 56 ff 15 ?? ?? ?? ?? 85 c0 74 30 6a 00 8d 8d e8 fb ff ff 51 8b 55 ec 52 8d 85 ec fb ff ff 50 57 ff 15 ?? ?? ?? ?? 85 c0 74 11 } //20
		$a_03_1 = {8d 7c 24 14 f3 ab 8b 4c 24 5c 89 44 24 04 89 44 24 08 c7 44 24 14 ?? ?? ?? ?? 89 44 24 0c 5f 89 44 24 0c 8b 41 04 85 c0 75 05 b8 ?? ?? ?? ?? 8d 54 24 00 8d 4c 24 10 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}