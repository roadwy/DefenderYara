
rule TrojanClicker_Win32_Foncsir_A{
	meta:
		description = "TrojanClicker:Win32/Foncsir.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 d2 52 50 8b c3 99 29 04 24 19 54 24 04 58 5a 83 fa 00 75 09 3d ?? ?? ?? ?? 72 df } //1
		$a_01_1 = {5b 6c 69 6e 6b 73 5d 00 } //1 汛湩獫]
		$a_01_2 = {5b 73 65 61 72 63 68 65 73 5d 00 } //1
		$a_01_3 = {2f 63 6f 6e 66 2e 70 68 70 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}