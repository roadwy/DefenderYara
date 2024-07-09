
rule PWS_Win32_Zbot_ED{
	meta:
		description = "PWS:Win32/Zbot.ED,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 04 68 00 30 00 00 a1 ?? ?? ?? 00 8b 40 50 50 a1 ?? ?? ?? 00 8b 40 34 50 a1 ?? ?? ?? 00 50 ff 15 ?? ?? ?? 00 a3 ?? ?? ?? 00 68 ?? ?? ?? 00 a1 ?? ?? ?? 00 8b 40 54 } //1
		$a_00_1 = {83 ff 21 75 07 bf 01 00 00 00 eb 06 83 ff 21 74 01 47 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}