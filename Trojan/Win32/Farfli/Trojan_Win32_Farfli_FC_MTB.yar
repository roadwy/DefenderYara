
rule Trojan_Win32_Farfli_FC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.FC!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b c8 8a 14 01 30 10 40 4e 75 f7 } //1
		$a_01_1 = {8b 54 24 08 8a 14 16 8b ce 83 e1 07 8b c6 d2 e2 c1 f8 03 03 c7 08 10 46 83 fe 40 7c e3 } //1
		$a_01_2 = {8a 1c 30 8b 55 10 30 1c 32 8a 14 32 30 14 30 8a 14 30 8b 5d 10 30 14 33 48 ff 45 10 8b d0 2b 55 10 83 fa 01 7d da } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}