
rule Trojan_Win64_NimLoadCrypt_LK_MTB{
	meta:
		description = "Trojan:Win64/NimLoadCrypt.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 d8 48 89 d9 48 c1 f8 ?? 48 c1 f9 10 31 d8 31 c8 48 89 d9 48 c1 f9 ?? 31 c8 30 44 ?? ?? 48 83 c3 01 4c 39 c3 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}