
rule Trojan_Win32_Pigax_gen_A{
	meta:
		description = "Trojan:Win32/Pigax.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 71 73 2e 76 64 63 } //2 oqs.vdc
		$a_03_1 = {eb 0f 8b 44 24 08 0f b6 04 08 83 f0 ?? 88 04 0b 41 39 d1 72 ed } //1
		$a_01_2 = {eb 15 0f b7 45 fe 01 f8 0f be 10 0f be 4f 02 31 ca 88 10 } //1
		$a_03_3 = {6a 00 6a 0a ff 75 fc e8 ?? ?? ?? ?? 09 c0 75 6f } //1
		$a_01_4 = {66 89 45 10 66 81 7d 10 94 01 75 0e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}