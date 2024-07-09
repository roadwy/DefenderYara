
rule Virus_Win32_Expiro_BAC_bit{
	meta:
		description = "Virus:Win32/Expiro.BAC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c3 83 c0 30 8b 00 8b 38 81 e7 df 00 df 00 8b 40 0c c1 e0 08 03 c7 } //1
		$a_03_1 = {4f 8b 3a 85 d8 81 f7 ?? ?? ?? ?? 3b c7 89 3b 8d 3a 48 48 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}