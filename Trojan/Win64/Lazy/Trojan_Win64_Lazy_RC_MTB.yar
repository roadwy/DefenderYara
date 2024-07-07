
rule Trojan_Win64_Lazy_RC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e2 99 ea f4 6e c4 16 cf f3 6b e8 b5 97 f8 0e 21 } //1
		$a_01_1 = {49 6f 6f 48 49 73 61 31 42 59 4a 2e 28 2a 41 79 78 57 59 55 62 29 2e 49 73 4c 6f 6f 70 62 61 63 6b } //1 IooHIsa1BYJ.(*AyxWYUb).IsLoopback
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}