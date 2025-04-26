
rule Trojan_Win32_Banload_E{
	meta:
		description = "Trojan:Win32/Banload.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 0e 32 5d 0c 88 19 41 4a 75 f4 } //1
		$a_01_1 = {81 38 33 c0 c2 08 74 9b } //1
		$a_01_2 = {8b 10 50 b9 ad de ef be 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}