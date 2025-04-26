
rule Trojan_Win32_Skintrim_gen_B{
	meta:
		description = "Trojan:Win32/Skintrim.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 73 72 63 00 } //-8
		$a_00_1 = {e0 00 0f 01 0b 01 06 00 } //10
		$a_00_2 = {4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } //10
		$a_02_3 = {8b c7 2b cf be ?? ?? ?? 00 8a 14 01 88 10 40 4e 75 f7 89 } //1
		$a_02_4 = {4f 75 f7 89 90 09 0f 00 8b ?? 2b ?? bf ?? ?? ?? ?? 8a 14 ?? 88 } //1
		$a_02_5 = {4a 75 f7 89 90 09 0f 00 8b ?? 2b ?? [ba be bf] ?? ?? ?? ?? 8a ?? ?? 88 } //1
	condition:
		((#a_00_0  & 1)*-8+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=21
 
}