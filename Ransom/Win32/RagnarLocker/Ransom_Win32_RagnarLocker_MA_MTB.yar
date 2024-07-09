
rule Ransom_Win32_RagnarLocker_MA_MTB{
	meta:
		description = "Ransom:Win32/RagnarLocker.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 8a 9c 35 ?? ?? ?? ?? 33 d2 0f b6 cb f7 75 0c 8b 45 08 0f b6 04 02 03 c7 03 c8 0f b6 f9 8a 84 3d 90 1b 00 88 84 35 90 1b 00 46 88 9c 3d 90 1b 00 81 fe ?? ?? ?? ?? 72 c3 } //1
		$a_03_1 = {40 8d 7f 01 0f b6 d0 89 55 14 8a 8c 15 ?? ?? ?? ?? 0f b6 c1 03 c3 0f b6 d8 8a 84 1d 90 1b 00 88 84 15 90 1b 00 8b 45 14 0f b6 d1 88 8c 1d 90 1b 00 0f b6 8c 05 90 1b 00 03 d1 0f b6 ca 0f b6 8c 0d 90 1b 00 30 4f ff 83 ee ?? 75 af } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}