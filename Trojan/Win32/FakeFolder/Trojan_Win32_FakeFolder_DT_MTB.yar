
rule Trojan_Win32_FakeFolder_DT_MTB{
	meta:
		description = "Trojan:Win32/FakeFolder.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e5 52 1d f8 e7 ec a9 3e fd ed 6e af 84 b2 fb 39 9c 1e fb 8b 78 1d ef ed e6 b4 7d f3 b3 74 ed b1 89 db 22 eb 5a b5 c5 1d 7e 91 88 d0 4b ac cd 28 3b c1 b2 3e eb 03 f8 ec 84 c0 e8 e5 07 88 88 c0 db } //1
		$a_01_1 = {62 0f a8 13 f1 20 56 73 9b 88 c9 82 13 de 92 08 8a ad 88 d4 44 e4 5e bf 87 47 22 c9 db dc 95 06 cd 8f 17 97 84 a3 fd 6b cd 75 96 a0 7e 19 f0 e4 e5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}