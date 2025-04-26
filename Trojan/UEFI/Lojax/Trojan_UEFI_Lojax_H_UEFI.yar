
rule Trojan_UEFI_Lojax_H_UEFI{
	meta:
		description = "Trojan:UEFI/Lojax.H!UEFI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {49 b9 03 00 00 00 00 00 00 80 [0-1f] ff ?? 08 [0-2f] ff ?? 28 [0-1f] ff ?? 10 } //1
		$a_03_1 = {48 8b c1 0f b6 00 83 f8 61 0f [0-25] 0f b6 40 01 85 c0 [0-26] 0f b6 40 02 83 f8 75 } //1
		$a_03_2 = {45 33 c9 45 33 c0 33 d2 48 8b ?? ?? ?? 48 8b ?? ?? ?? 48 8b ?? ?? 48 8b ?? ?? ?? ?? ?? ff 90 90 08 01 00 00 } //1
		$a_00_3 = {4d 9b 2d 83 d5 d8 5f 42 bd 52 5c 5a fb 2c 85 dc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}