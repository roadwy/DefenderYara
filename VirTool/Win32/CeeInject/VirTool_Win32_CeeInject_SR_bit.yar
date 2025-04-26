
rule VirTool_Win32_CeeInject_SR_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 50 ff 75 ?? ff 75 ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? ff d0 } //1
		$a_01_1 = {8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 } //1
		$a_03_2 = {8b ca 33 c1 8b d2 c7 45 fc 00 00 00 00 8b d2 01 45 fc 8b d2 8b 0d ?? ?? ?? ?? 8b 55 fc 89 11 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}