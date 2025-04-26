
rule Ransom_Win32_HydraCrypt_NH_MTB{
	meta:
		description = "Ransom:Win32/HydraCrypt.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 0c 03 05 ?? ?? ?? 00 51 03 d6 } //3
		$a_03_1 = {83 c0 c0 50 a1 ?? ?? ?? 00 8d 56 40 52 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}