
rule Ransom_Win32_GandCrab_AG_bit{
	meta:
		description = "Ransom:Win32/GandCrab.AG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 3d 00 01 00 00 75 f2 90 09 06 00 88 80 ?? ?? ?? 00 } //1
		$a_03_1 = {33 d2 8a 9d ?? ?? ?? 00 8b c5 0f b6 cb f7 f7 0f be 82 ?? ?? ?? 00 03 c6 03 c8 0f b6 f1 8a 86 ?? ?? ?? 00 88 85 ?? ?? ?? 00 45 88 9e ?? ?? ?? 00 81 fd 00 01 00 00 75 } //1
		$a_03_2 = {30 04 2e 83 ee 01 79 e5 5f 5e 5d 59 59 c3 90 09 13 00 81 fe ?? ?? 00 00 7d 06 ff 15 ?? ?? ?? 00 e8 b7 fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}