
rule Trojan_Win64_ValleyRat_RY_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.RY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 0f 48 63 6c 24 ?? 48 69 dd ?? ?? ?? ?? 48 89 de 48 c1 ee ?? 48 c1 eb 20 01 f3 01 db 8d 1c 5b 29 dd 48 63 ed 32 94 2c ?? ?? ?? ?? 88 14 0f 8b 4c 24 ?? 83 c1 01 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}