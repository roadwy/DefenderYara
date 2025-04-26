
rule TrojanDropper_Win32_HurlyBurly_A_dha{
	meta:
		description = "TrojanDropper:Win32/HurlyBurly.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6b 69 6e 5f 69 6e 73 74 61 6c 6c 20 25 73 00 } //2 歳湩楟獮慴汬┠s
		$a_03_1 = {ff ff 71 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 6d c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 6b c6 85 ?? ?? ff ff 6b } //2
		$a_01_2 = {28 00 43 00 29 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 73 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 } //2 (C) Microsofts Corporation.
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}