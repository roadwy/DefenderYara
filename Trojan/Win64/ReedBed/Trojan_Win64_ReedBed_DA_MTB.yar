
rule Trojan_Win64_ReedBed_DA_MTB{
	meta:
		description = "Trojan:Win64/ReedBed.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 2b c8 49 0f af cf 0f b6 44 ?? ?? 41 32 44 ?? fc 41 88 40 ff 49 ff cc 0f 85 } //10
		$a_03_1 = {48 2b c8 49 0f af cf 0f b6 44 ?? ?? 42 32 44 ?? fc 41 88 40 ff 49 ff cc 0f 85 } //10
		$a_03_2 = {48 2b c8 49 0f af cf 0f b6 44 ?? ?? 43 32 44 ?? fc 41 88 40 ff 49 ff cc 0f 85 } //10
		$a_01_3 = {48 63 c8 48 8b c3 48 f7 e1 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1) >=11
 
}