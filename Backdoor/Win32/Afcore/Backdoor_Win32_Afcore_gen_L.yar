
rule Backdoor_Win32_Afcore_gen_L{
	meta:
		description = "Backdoor:Win32/Afcore.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 45 fc 33 10 8b 0d ?? ?? ?? 00 03 4d fc 89 11 eb b3 } //1
		$a_00_1 = {c7 45 a4 05 20 40 00 8b 4d a4 8b 51 fc 89 95 60 fe ff ff 8b 85 60 fe ff ff 50 } //1
		$a_00_2 = {33 c9 81 e9 bc 01 00 00 64 8b 89 d4 01 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}