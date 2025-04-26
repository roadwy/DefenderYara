
rule Trojan_Win32_Mansabo_RPX_MTB{
	meta:
		description = "Trojan:Win32/Mansabo.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 6e 00 6f 00 20 00 53 00 65 00 74 00 75 00 70 00 } //1 Inno Setup
		$a_01_1 = {72 00 6f 00 63 00 6b 00 73 00 64 00 61 00 6e 00 69 00 73 00 74 00 65 00 72 00 } //1 rocksdanister
		$a_01_2 = {4c 00 69 00 76 00 65 00 6c 00 79 00 20 00 57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 } //1 Lively Wallpaper
		$a_01_3 = {32 00 2e 00 30 00 2e 00 36 00 2e 00 31 00 } //1 2.0.6.1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}