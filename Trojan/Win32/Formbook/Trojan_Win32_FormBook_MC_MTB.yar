
rule Trojan_Win32_FormBook_MC_MTB{
	meta:
		description = "Trojan:Win32/FormBook.MC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 e3 e8 eb 00 00 81 e1 8d 32 00 00 f7 d3 c2 51 57 5b 81 c1 c7 75 01 00 49 81 c3 f3 bd 00 00 b8 61 12 00 00 81 f3 97 94 00 00 81 fa 81 a8 00 00 74 0f 41 f7 d1 c2 2e 71 b9 67 43 00 00 48 c2 1f de 81 f2 9d 35 00 00 4b bb 05 31 00 00 c2 70 35 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}