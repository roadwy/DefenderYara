
rule Trojan_Win32_Desurou_B{
	meta:
		description = "Trojan:Win32/Desurou.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 00 01 00 00 99 f7 f9 8b 45 ?? 30 10 8b 45 ?? 40 3b 45 ?? 89 45 ?? 7c df } //1
		$a_03_1 = {81 7d 0c fa 00 00 00 0f 85 ?? ?? 00 00 83 7f 08 05 0f 82 } //1
		$a_01_2 = {00 63 73 79 73 2e 64 61 74 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}