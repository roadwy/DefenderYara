
rule Trojan_Win32_Pony_AP_MTB{
	meta:
		description = "Trojan:Win32/Pony.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 01 1b a5 5a 3b 9b 49 ad e0 44 2c 34 91 40 1c 2f 60 11 1d 8e 13 19 51 aa 65 21 4e 03 42 43 f1 b3 89 ec 76 } //1
		$a_01_1 = {44 fb fa 14 9f 98 35 94 6f d3 07 ae 96 9e fa 66 42 98 86 37 43 f8 7d 83 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}