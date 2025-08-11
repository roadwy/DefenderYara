
rule Trojan_Win32_Reconyc_GVB_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {96 8e fd 44 dd a1 8a f3 5a e5 b6 07 02 3c 25 83 ae ec 78 b5 de a7 07 0d d2 15 82 dd 02 63 a3 b5 7a 7f d9 0f 9a 51 72 0d 3e 5b 89 e4 64 ce 6c 2d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}