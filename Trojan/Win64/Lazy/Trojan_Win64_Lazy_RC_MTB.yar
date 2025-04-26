
rule Trojan_Win64_Lazy_RC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e2 99 ea f4 6e c4 16 cf f3 6b e8 b5 97 f8 0e 21 } //1
		$a_01_1 = {49 6f 6f 48 49 73 61 31 42 59 4a 2e 28 2a 41 79 78 57 59 55 62 29 2e 49 73 4c 6f 6f 70 62 61 63 6b } //1 IooHIsa1BYJ.(*AyxWYUb).IsLoopback
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Lazy_RC_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 ba 00 10 00 00 00 00 00 00 49 b8 ?? ?? 00 00 00 00 00 00 65 48 8b 04 25 60 00 00 00 48 8b 40 10 48 01 c2 49 01 c0 4c 8b ca 48 31 0a 48 83 c2 08 49 3b d0 72 f4 41 ff e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}