
rule Trojan_Win32_Ekstak_ASGL_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {65 00 ff d6 68 ?? ?? 65 00 ff 15 ?? ?? 65 00 68 ?? ?? 65 00 50 ff d6 85 c0 5e 74 1d 6a 00 6a 00 68 ?? ?? 65 00 68 ?? ?? ?? 00 ff d0 ff 15 ?? ?? 65 00 48 f7 d8 1b c0 f7 d8 c3 } //2
		$a_01_1 = {7b 63 66 35 65 62 66 34 36 2d 65 33 62 36 2d 34 34 39 61 2d 62 35 36 62 2d 35 36 38 66 38 34 33 66 37 38 31 34 7d } //2 {cf5ebf46-e3b6-449a-b56b-568f843f7814}
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}