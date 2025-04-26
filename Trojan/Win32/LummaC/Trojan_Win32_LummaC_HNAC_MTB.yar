
rule Trojan_Win32_LummaC_HNAC_MTB{
	meta:
		description = "Trojan:Win32/LummaC.HNAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 07 00 00 "
		
	strings :
		$a_01_0 = {08 c1 88 e8 30 c8 } //10
		$a_03_1 = {0f af c8 89 ca 89 c8 89 cf f7 d2 [0-10] 21 ?? 81 ?? ?? ?? ?? ?? (81|89) } //5
		$a_03_2 = {0f af c8 89 ca 89 cb f7 d2 89 [0-15] 25 ?? ?? ?? ?? 81 } //5
		$a_01_3 = {8d 48 ff 0f af c8 89 } //1
		$a_01_4 = {8d 69 ff 0f af e9 89 } //1
		$a_01_5 = {09 ce 89 c1 f7 d1 31 d6 89 c2 } //1
		$a_03_6 = {0f 9c 44 24 0b [0-b0] 80 ?? 01 80 ?? 01 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=17
 
}