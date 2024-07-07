
rule Ransom_Win32_Genasom_BA_MTB{
	meta:
		description = "Ransom:Win32/Genasom.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 06 83 6c 24 90 01 01 01 8b 44 24 90 01 01 85 c0 7d 90 00 } //1
		$a_02_1 = {0f b6 c1 03 05 90 01 04 25 ff 00 00 00 8a 90 01 05 88 88 90 01 04 88 96 90 01 04 0f b6 b0 90 01 04 0f b6 d2 03 f2 81 e6 ff 00 00 00 81 3d 90 01 04 81 0c 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}