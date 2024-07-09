
rule Trojan_Win32_Aclako_gen_A{
	meta:
		description = "Trojan:Win32/Aclako.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 45 ff 46 88 07 47 4b 75 e6 0f b7 45 ?? 8b 4d } //1
		$a_01_1 = {81 f1 4d 5a 00 00 66 89 0f 8b 4f 3c } //1
		$a_03_2 = {80 3f 4d 0f 85 ?? ?? ?? ?? 80 7f 01 5a 0f 85 ?? ?? ?? ?? be 04 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}