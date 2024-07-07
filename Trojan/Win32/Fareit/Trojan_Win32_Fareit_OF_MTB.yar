
rule Trojan_Win32_Fareit_OF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.OF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 81 fa 81 7f f5 41 81 fb d2 b6 5e 1b 85 db 66 81 fb ae 75 66 85 d2 ff e0 eb 02 00 00 81 ff 9f 7f b5 d9 81 ff a4 d0 62 ab 85 c0 66 81 fa 97 f5 0f 6e da 66 85 d2 31 f1 81 ff ff 1c d6 a1 eb 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}