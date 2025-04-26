
rule Ransom_Win32_GandCrab_AF_bit{
	meta:
		description = "Ransom:Win32/GandCrab.AF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 00 04 00 00 38 11 74 0c 85 c0 74 08 42 48 80 3c 0a 00 75 f4 e8 ?? ?? ff ff eb 08 e8 ?? ?? ff ff 30 04 37 4e 79 f5 } //1
		$a_03_1 = {88 0c 30 46 3b 35 ?? ?? ?? 00 72 cc 90 09 19 00 57 57 ff 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 8a 8c 30 ?? ?? 00 00 a1 ?? ?? ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}