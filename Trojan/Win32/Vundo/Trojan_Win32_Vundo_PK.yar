
rule Trojan_Win32_Vundo_PK{
	meta:
		description = "Trojan:Win32/Vundo.PK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 2d ?? 00 00 00 85 c0 74 } //1
		$a_01_1 = {8a 23 93 32 df 93 88 03 } //10
		$a_03_2 = {0f b6 00 83 e8 ?? 85 c0 74 90 09 0b 00 a1 ?? ?? ?? ?? 2b 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1) >=11
 
}