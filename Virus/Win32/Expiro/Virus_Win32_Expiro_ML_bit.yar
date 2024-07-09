
rule Virus_Win32_Expiro_ML_bit{
	meta:
		description = "Virus:Win32/Expiro.ML!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 f1 83 c1 30 8b 09 8b 01 81 e0 df 00 df 00 8b 49 0c c1 e1 08 01 c1 } //1
		$a_03_1 = {40 8b 03 85 c1 35 ?? ?? ?? ?? 39 c3 89 06 8b c6 43 83 c6 04 83 e9 04 43 43 43 83 f9 00 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}