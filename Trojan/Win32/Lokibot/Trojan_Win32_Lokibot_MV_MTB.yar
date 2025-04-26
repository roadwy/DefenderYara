
rule Trojan_Win32_Lokibot_MV_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {78 59 6f 68 63 34 41 45 61 59 62 4e 43 53 37 5a 65 53 56 51 4b 61 46 76 53 56 69 57 58 } //xYohc4AEaYbNCS7ZeSVQKaFvSViWX  1
		$a_80_1 = {38 62 35 63 6c 6b 56 55 53 66 32 4c 65 4f 39 70 45 34 56 6e 6f 66 49 75 76 } //8b5clkVUSf2LeO9pE4VnofIuv  1
		$a_00_2 = {33 c0 8a c3 8a 98 48 30 46 00 33 c0 8a c3 8b d6 } //1
		$a_00_3 = {6a 04 68 00 30 00 00 68 0b b6 3f 28 6a 00 e8 } //1
		$a_00_4 = {8a 00 88 45 ef 90 90 8a 45 ef 34 2d 8b 55 08 03 55 f8 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}