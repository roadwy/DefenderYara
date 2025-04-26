
rule Trojan_Win32_LummaC_BV_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 0c 16 30 d9 88 0c 16 42 39 94 24 } //3
		$a_01_1 = {d0 e9 00 d9 0f b6 c9 8d 1c 49 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}