
rule Ransom_Win32_Genasom_AGM_MTB{
	meta:
		description = "Ransom:Win32/Genasom.AGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c5 89 45 fc 56 8b f1 e8 ?? ?? ?? ?? 85 c0 75 47 56 68 14 33 40 00 } //2
		$a_03_1 = {68 24 33 40 00 50 ff 15 ?? ?? ?? ?? 8b f0 83 c4 18 85 f6 74 15 68 28 33 40 00 56 } //2
		$a_01_2 = {0f 10 04 2f 0f 28 ca 0f 57 c8 0f 11 0c 2f 83 c7 10 83 ff 20 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}