
rule Trojan_Win64_Midie_MX_MTB{
	meta:
		description = "Trojan:Win64/Midie.MX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 48 48 89 c7 48 8d 0d 7c 01 00 00 ba 01 00 00 00 49 c7 c0 24 00 00 00 49 89 f9 48 83 ec 08 50 48 8d 05 0c 00 00 00 48 89 44 24 08 58 ff 25 80 09 00 00 48 89 f9 ff 15 6f 09 00 00 4c 8d 0d 45 01 00 00 49 c7 c2 24 00 00 00 } //1
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 } //1 CreateMutex
		$a_01_2 = {41 78 6f 6c 6f 74 6c } //1 Axolotl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}