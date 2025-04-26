
rule Ransom_Win32_Roger_MKV_MTB{
	meta:
		description = "Ransom:Win32/Roger.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 3c 8b 7c 24 4c 8b 2d ?? ?? ?? ?? 32 c3 03 5c 24 5c 88 01 8b 44 24 34 01 44 24 28 47 89 5c 24 48 89 7c 24 4c 3b 7e 04 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}