
rule Trojan_Win64_Redcap_KGF_MTB{
	meta:
		description = "Trojan:Win64/Redcap.KGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 0f b6 44 0c 20 43 32 04 0a 41 88 01 } //2
		$a_01_1 = {44 5e 47 77 73 2a 66 21 38 77 45 4e 72 39 64 25 49 23 5e 52 4d 65 } //1 D^Gws*f!8wENr9d%I#^RMe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}