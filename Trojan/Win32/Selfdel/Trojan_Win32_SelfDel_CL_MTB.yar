
rule Trojan_Win32_SelfDel_CL_MTB{
	meta:
		description = "Trojan:Win32/SelfDel.CL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {bd 38 a6 3f 7d 81 ed dd f2 9f 6c f7 dd 55 ff 0c 24 5d 81 f5 37 83 87 89 01 e8 5d 01 f0 2d 93 cf e7 66 } //1
		$a_01_1 = {01 ee 66 81 f3 2f ec 01 eb 8b 1b 8b 1b 31 1e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}