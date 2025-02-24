
rule Trojan_Win32_ICLoader_BAL_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 00 0b ca 89 4c 24 04 df 6c 24 04 dc 05 ?? ?? 4d 00 dd 1d ?? ?? 4d 00 ff 15 ?? ?? 4c 00 a3 ?? ?? 4d 00 83 c4 08 c3 } //4
		$a_03_1 = {55 8b ec 83 ec 10 53 56 57 e8 ?? ?? f5 ff 89 45 fc e9 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}