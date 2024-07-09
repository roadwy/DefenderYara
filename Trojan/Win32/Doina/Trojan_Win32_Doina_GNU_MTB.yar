
rule Trojan_Win32_Doina_GNU_MTB{
	meta:
		description = "Trojan:Win32/Doina.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 33 b5 80 2b 26 d5 77 f7 fa a2 cd 63 7e 1a 95 23 76 f9 } //10
		$a_03_1 = {41 69 7c 7d ?? 8a 41 6c a1 89 dc 29 ce 83 a9 } //10
		$a_01_2 = {2e 76 6d 70 31 } //1 .vmp1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1) >=21
 
}