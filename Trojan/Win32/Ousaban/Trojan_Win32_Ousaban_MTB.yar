
rule Trojan_Win32_Ousaban_MTB{
	meta:
		description = "Trojan:Win32/Ousaban!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5e 37 24 44 67 5a e9 42 8d 94 ab 7f 58 c7 cd 67 0f d4 a5 a6 40 a4 59 9a 06 e2 b0 1b 99 47 77 a4 74 96 a3 5d 4e 17 a8 44 ca f6 c2 79 a9 ac cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}