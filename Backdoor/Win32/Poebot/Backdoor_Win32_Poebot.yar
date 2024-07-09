
rule Backdoor_Win32_Poebot{
	meta:
		description = "Backdoor:Win32/Poebot,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 35 ?? ?? ?? 00 68 ?? ?? ?? 00 8d 85 a4 ee ff ff 50 e8 ?? ?? 00 00 83 c4 20 83 a5 d8 ee ff ff 00 eb 0d 8b 85 d8 ee ff ff 40 89 85 d8 ee ff ff 83 bd d8 ee ff ff 0a 75 05 e8 } //1
		$a_02_1 = {8d 85 a4 ee ff ff 50 e8 89 02 00 00 83 c4 20 89 bd d8 ee ff ff 83 bd d8 ee ff ff 0a 75 05 e8 ?? ?? ff ff 68 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}