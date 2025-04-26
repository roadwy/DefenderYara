
rule Ransom_Win32_Nasan_B_bit{
	meta:
		description = "Ransom:Win32/Nasan.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 34 8b 04 f5 ?? ?? ?? 00 0f b7 d7 66 0f be 0c 10 b8 ff 00 00 00 66 33 cf 66 23 c8 0f b6 04 f5 ?? ?? ?? 00 66 33 c8 47 66 89 0c 53 66 3b 3c f5 ?? ?? ?? 00 72 cc } //1
		$a_03_1 = {73 24 8b 04 f5 ?? ?? ?? 00 0f b7 ca 8a 04 08 32 04 f5 ?? ?? ?? 00 32 c2 42 88 04 39 66 3b 14 f5 ?? ?? ?? 00 72 dc } //1
		$a_03_2 = {6a 07 59 e8 b8 05 00 00 6a 0e 8d 54 24 10 59 e8 64 05 00 00 8d 44 24 28 50 ff 15 ?? ?? ?? 00 33 ed 45 85 c0 74 13 8d 4c 24 0c 51 50 ff 15 ?? ?? ?? 00 85 c0 74 03 55 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}