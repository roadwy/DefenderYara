
rule Ransom_Win32_Reveton_U{
	meta:
		description = "Ransom:Win32/Reveton.U,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 b8 7e 2a 00 00 00 0f 85 ?? ?? 00 00 8d 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 80 e4 2a 00 00 e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 66 ba 50 00 } //1
		$a_03_1 = {9a 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 90 09 03 00 c7 } //1
		$a_01_2 = {69 6d 70 6d 74 63 6e 67 74 2c 61 6d 6f } //1 impmtcngt,amo
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}