
rule Ransom_Win32_Nokonoko_PYE_MTB{
	meta:
		description = "Ransom:Win32/Nokonoko.PYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 4d a8 03 ca 42 8a 04 19 32 01 88 04 31 3b d7 } //1
		$a_03_1 = {33 ca 8b d1 8b c1 c1 e8 10 81 e2 00 00 ff 00 0b d0 8b c1 c1 e0 10 81 e1 00 ff 00 00 0b c1 c1 ea 08 0f b6 8f 90 01 04 c1 e0 08 0b d0 0f b6 87 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}