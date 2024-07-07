
rule Trojan_Win32_InjectorCrypt_SK_MTB{
	meta:
		description = "Trojan:Win32/InjectorCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_12_0 = {5e 5b c9 c2 0c 00 90 0a 80 00 55 89 e5 83 ec 28 53 56 57 01 db 8b 75 08 43 89 f7 11 d9 eb 90 02 05 8b 5d 10 87 d1 83 7d 0c 00 74 90 00 01 } //1
		$a_5f_1 = {5b c9 c2 0c 00 90 0a 50 00 09 d9 ac 6b d2 90 01 01 eb } //16128
	condition:
		((#a_12_0  & 1)*1+(#a_5f_1  & 1)*16128) >=2
 
}