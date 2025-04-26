
rule Trojan_Win32_LummaStealer_NDT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 eb 02 33 f6 33 db 56 e8 36 c6 ff ff 59 8b c3 8d 65 ec 5f 5e 5b 8b 4d fc 33 cd e8 89 3f ff ff c9 c3 } //2
		$a_01_1 = {59 59 33 c0 8d 65 cc 5f 5e 5b 8b 4d fc 33 cd e8 ce 15 ff ff c9 c3 33 c0 50 50 50 } //2
		$a_01_2 = {eb 05 83 ca ff 8b c2 5f 5e 8b 4d fc 33 cd 5b e8 d1 b2 ff ff c9 c3 8b ff 55 8b ec 83 ec 24 53 56 57 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}