
rule Trojan_Win32_Ekstak_HNA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 57 06 d4 52 ad 92 1c fe f2 25 ea 43 4d 9e 0c e2 a1 55 0f 00 16 9b 15 81 b5 ae b9 59 88 e7 96 } //2
		$a_01_1 = {bf f5 ce 5e 7e 96 92 14 ff 97 4f a2 6f e7 f2 c9 49 d0 0f d4 f7 00 4d a2 78 ec 07 d6 2b cc 63 49 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}