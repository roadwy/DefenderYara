
rule Trojan_Win64_Tedy_TMX_MTB{
	meta:
		description = "Trojan:Win64/Tedy.TMX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 c0 10 31 d2 48 3b 95 f0 02 00 00 48 8d 95 f8 02 00 00 48 0f 41 ca 4c 8b 09 48 8d 8d } //1
		$a_01_1 = {70 69 6e 74 65 73 74 2e 65 78 65 } //1 pintest.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}