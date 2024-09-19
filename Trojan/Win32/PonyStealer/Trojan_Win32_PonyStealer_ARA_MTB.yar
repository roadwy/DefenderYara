
rule Trojan_Win32_PonyStealer_ARA_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 37 0f 65 f7 66 0f 6a d7 66 0f 71 f6 64 66 0f db f9 66 0f ec c6 66 0f 69 ce 0f df fd 66 0f 60 f0 66 0f dc fd 83 c7 04 0f eb e0 0f dd e7 66 0f df f5 0f 6b d9 0f 72 f3 f8 66 0f d8 db 0f 73 f5 c8 0f e5 d5 66 0f 72 d1 fe 81 7f fc 70 70 70 70 75 ae 0f 66 fe 66 0f e9 c6 0f 64 c8 0f f5 ea 5f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}