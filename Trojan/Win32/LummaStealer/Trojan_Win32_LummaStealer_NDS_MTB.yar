
rule Trojan_Win32_LummaStealer_NDS_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 eb 02 33 f6 33 db 56 e8 d6 db ff ff 59 8b c3 8d 65 ec 5f 5e 5b 8b 4d fc 33 cd e8 } //2
		$a_01_1 = {75 ef 56 e8 a4 03 00 00 eb 06 56 e8 83 00 00 00 33 c0 59 8b 4d fc 5f 5e 33 cd 5b e8 f4 96 ff ff c9 c3 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_LummaStealer_NDS_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.NDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 5a 4a 76 73 73 2d 2d } //2 CZJvss--
		$a_01_1 = {f7 d5 21 eb 09 f3 f7 d0 21 c7 09 cf 89 dd 0f a4 fd 01 8d 34 3f f7 d5 f7 d6 01 fe 11 dd } //1
		$a_01_2 = {0f b7 c0 89 c6 f7 d6 0f b7 c9 21 ce f7 d1 21 c1 31 c0 39 ce 0f 94 c0 8b 4c 24 04 } //1
		$a_01_3 = {31 d1 69 c9 93 01 00 01 0f be 50 01 31 ca 69 ca 93 01 00 01 0f be 50 02 31 ca 69 ca 93 01 00 01 0f be 50 03 83 c0 04 31 ca } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}