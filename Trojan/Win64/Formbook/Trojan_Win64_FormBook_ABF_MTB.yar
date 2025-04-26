
rule Trojan_Win64_FormBook_ABF_MTB{
	meta:
		description = "Trojan:Win64/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 05 f9 16 45 00 48 8d 15 e2 64 3a 00 48 8d 0d 03 65 3a 00 e8 ?? ?? ?? ?? 4c 8d 05 9f 57 44 00 33 d2 48 8d 0d 0e 65 3a 00 e8 ?? ?? ?? ?? 4c 8d 05 da 16 45 00 48 8d 15 1b 65 3a 00 48 8d 0d 7c 66 3a 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}