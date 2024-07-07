
rule Trojan_Win32_Azorult_GU_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GU!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 33 ff 33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db 8b c3 89 44 24 1c 61 c3 } //1
		$a_01_1 = {89 45 f8 c6 45 dc 6e c6 45 dd 74 c6 45 de 64 c6 45 df 6c c6 45 e0 6c c6 45 e1 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}