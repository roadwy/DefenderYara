
rule Ransom_Win32_LockBit_AD{
	meta:
		description = "Ransom:Win32/LockBit.AD,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {8b 0e 0f b6 d1 0f b6 dd 57 8d bd fc fe ff ff 8a 04 3a 8a 24 3b c1 e9 10 83 c6 04 0f b6 d1 0f b6 cd 8a 1c 3a 8a 3c 39 5f 8a d4 8a f3 c0 e0 02 c0 eb 02 c0 e6 06 c0 e4 04 c0 ea 04 0a fe 0a c2 0a e3 88 07 88 7f 02 88 67 01 ff 4d fc 8d 7f 03 75 af 58 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10) >=11
 
}