
rule Trojan_Win32_AsyncRAT_DAX_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 00 00 84 3d af 15 5b e1 2e 49 80 2f 64 9d 1b 15 09 66 9a da 12 8d 35 02 3a 46 b1 18 e9 87 23 f0 39 75 3a 4f ad 33 99 66 cf 11 b7 } //1
		$a_01_1 = {bb 4f 8e 27 d1 e5 28 8a 54 7e 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}