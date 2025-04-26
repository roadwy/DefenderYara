
rule Trojan_Win64_Lazy_HNC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.HNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 61 64 67 61 65 6c 61 64 69 61 64 64 61 83 a5 a2 a3 a6 55 6d 55 64 67 61 65 6c 61 66 63 } //1
		$a_01_1 = {96 62 64 56 54 88 99 a7 a8 7d 78 71 56 56 63 72 41 3e b0 84 00 00 5a 85 00 00 66 64 69 73 6b 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}