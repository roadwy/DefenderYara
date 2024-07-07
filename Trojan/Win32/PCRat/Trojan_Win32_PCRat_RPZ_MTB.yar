
rule Trojan_Win32_PCRat_RPZ_MTB{
	meta:
		description = "Trojan:Win32/PCRat.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 4c 24 14 68 00 10 00 00 51 50 ff 15 90 01 04 8b e8 85 ed 7e 32 8b 53 04 8b cd 8d 74 24 10 8d 7c 1a 10 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8b 4b 04 03 cd 8b c1 89 4b 04 3d 5c dd 04 00 73 08 8b 43 08 83 f8 ff 75 b5 90 00 } //1
		$a_01_1 = {31 31 32 2e 32 31 33 2e 31 31 37 2e 34 32 3a 31 31 35 30 } //1 112.213.117.42:1150
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}