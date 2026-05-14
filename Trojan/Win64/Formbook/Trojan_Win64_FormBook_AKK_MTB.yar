
rule Trojan_Win64_FormBook_AKK_MTB{
	meta:
		description = "Trojan:Win64/FormBook.AKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 05 b8 f9 02 00 48 8d 54 24 20 0f 10 00 0f 11 05 c9 86 03 00 e8 ?? ?? ?? ?? 4c 8d 05 ad f9 02 00 48 8d 54 24 20 0f 10 00 0f 11 05 1e 87 03 00 e8 ?? ?? ?? ?? 4c 8d 05 aa f9 02 00 48 8d 54 24 20 0f 10 00 0f 11 05 c3 86 03 00 e8 ?? ?? ?? ?? 4c 8d 05 a7 f9 02 00 48 8d 54 24 20 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}