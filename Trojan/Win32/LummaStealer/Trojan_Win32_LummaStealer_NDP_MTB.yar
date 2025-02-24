
rule Trojan_Win32_LummaStealer_NDP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 85 e4 fd ff ff 83 c4 10 8b 4d fc 33 cd e8 1c 88 fe ff c9 c3 8b ff 55 8b ec 6a 04 6a 00 ff 75 08 6a 00 } //2
		$a_01_1 = {30 ca 88 e8 30 cd 20 c8 88 d1 08 c5 f6 d1 88 e8 20 e9 08 d5 f6 d0 20 c2 88 e8 08 ca 30 d0 0f 45 f7 84 d2 } //1
		$a_01_2 = {89 c8 89 ce f7 d0 81 f6 ce 0f 71 d9 89 c2 21 ce 81 e2 ce 0f 71 d9 89 d7 21 f7 31 d6 09 fe 89 f2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}