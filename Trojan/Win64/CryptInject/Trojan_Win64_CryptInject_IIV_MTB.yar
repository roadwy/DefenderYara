
rule Trojan_Win64_CryptInject_IIV_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.IIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b c0 48 8d 5b 01 b8 39 8e e3 38 41 f7 e8 d1 fa 8b ca c1 e9 1f 03 d1 8d 0c d2 44 2b c1 41 ff c0 44 30 43 ff 48 83 ef 01 75 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}