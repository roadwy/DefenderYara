
rule Trojan_Win32_Tedy_SXJ_MTB{
	meta:
		description = "Trojan:Win32/Tedy.SXJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 8d 55 b8 8d 4d a0 e8 45 e8 ?? ?? ?? ?? 04 68 88 13 00 00 c6 45 fc 02 ff 15 ?? ?? ?? ?? 8d 8d 64 ff ff ff e8 ?? ?? ?? ?? 51 8b d0 c6 45 fc 03 8d 8d 7c ff ff ff } //20
		$a_80_1 = {5c 53 68 65 6c 6c 5c 4d 61 6e 61 67 65 5c 63 6f 6d 6d 61 6e 64 } //\Shell\Manage\command  10
		$a_80_2 = {73 65 74 75 70 2e 65 78 65 } //setup.exe  5
	condition:
		((#a_03_0  & 1)*20+(#a_80_1  & 1)*10+(#a_80_2  & 1)*5) >=35
 
}