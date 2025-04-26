
rule Trojan_Win32_LummaC_AST_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 10 0f b6 45 ?? 0f b6 84 05 ?? ?? ?? ?? 31 d0 88 45 ?? 8b 55 ?? 8b 45 ?? 01 c2 0f b6 45 ?? 88 02 83 45 ?? 01 8b 45 ?? 3b 45 ?? 0f 8f } //4
		$a_01_1 = {01 ca 0f b6 00 88 02 8b 55 0c 8b 45 08 01 c2 0f b6 45 ff 88 02 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}