
rule Virus_Win32_Expiro_MI_bit{
	meta:
		description = "Virus:Win32/Expiro.MI!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 5f 30 8b 03 81 e0 df 00 df 00 8b 5b 0c c1 e3 08 03 d8 c1 eb 02 81 } //1
		$a_03_1 = {48 8b 06 85 c3 35 ?? ?? ?? ?? 39 c7 89 07 29 d8 83 c6 04 4b 83 c7 04 4b 4b 4b 83 fb 00 74 05 } //1
		$a_01_2 = {b8 0a 00 00 00 99 f7 fb 89 45 f0 8b 45 20 03 45 18 01 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}