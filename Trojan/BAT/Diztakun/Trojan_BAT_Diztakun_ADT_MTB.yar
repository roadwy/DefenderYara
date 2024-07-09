
rule Trojan_BAT_Diztakun_ADT_MTB{
	meta:
		description = "Trojan:BAT/Diztakun.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 06 07 6f ?? ?? ?? 0a 00 00 de 0b 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 07 28 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 00 07 28 ?? ?? ?? 0a 13 04 11 04 2c 09 00 07 28 } //2
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //1 DisableRegistryTools
		$a_01_3 = {45 00 61 00 73 00 79 00 2d 00 54 00 6f 00 6f 00 6c 00 4b 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //1 Easy-ToolKit.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}