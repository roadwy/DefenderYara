
rule Trojan_Win32_LummaC_FAG_MTB{
	meta:
		description = "Trojan:Win32/LummaC.FAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 0c 16 30 d9 88 0c 16 42 39 94 24 ?? ?? ?? ?? 89 f9 0f 84 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_LummaC_FAG_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.FAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 55 ff 8b 45 08 03 45 f4 0f b6 08 33 ca 8b 55 08 03 55 f4 88 0a e9 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}