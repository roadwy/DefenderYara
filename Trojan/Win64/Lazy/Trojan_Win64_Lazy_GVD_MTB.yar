
rule Trojan_Win64_Lazy_GVD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 ?? 8c 24 [0-05] 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 88 01 } //2
		$a_02_1 = {48 03 d1 48 8b ca 0f b6 09 03 c8 8b c1 48 ?? 8c 24 [0-05] 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 88 01 e9 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}