
rule Trojan_Win32_ValleyRat_AVY_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.AVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 a8 49 c6 45 a9 6e c6 45 aa 74 c6 45 ab 65 c6 45 ac 72 c6 45 ad 6e c6 45 ae 65 c6 45 af 74 c6 45 b0 4f c6 45 b1 70 c6 45 b2 65 c6 45 b3 6e c6 45 b4 41 c6 45 b5 00 c6 45 94 49 c6 45 95 6e c6 45 96 74 c6 45 97 65 c6 45 98 72 c6 45 99 6e c6 45 9a 65 c6 45 9b 74 c6 45 9c 43 c6 45 9d 6f c6 45 9e 6e c6 45 9f 6e c6 45 a0 65 c6 45 a1 63 c6 45 a2 74 c6 45 a3 41 c6 45 a4 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}