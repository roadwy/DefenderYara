
rule Trojan_Win32_Wrokni_AD_MTB{
	meta:
		description = "Trojan:Win32/Wrokni.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {0f b6 02 50 b8 90 01 04 ff e0 8b f9 90 90 58 2b c1 50 b8 90 01 04 ff e0 f7 90 00 } //2
		$a_02_1 = {58 8b 4d 08 50 b8 90 01 04 ff e0 90 00 } //1
		$a_02_2 = {58 03 4d fc 50 b8 90 01 04 ff e0 90 00 } //1
		$a_02_3 = {58 88 01 50 b8 90 01 04 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=5
 
}