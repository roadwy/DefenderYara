
rule Trojan_Win32_Alureon_GO{
	meta:
		description = "Trojan:Win32/Alureon.GO,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 00 66 00 6c 00 73 00 64 00 6b 00 6a 00 66 00 30 00 30 00 31 00 2e 00 64 00 61 00 74 00 } //10 jflsdkjf001.dat
		$a_01_1 = {c7 45 80 6c 00 6c 00 c7 45 86 32 00 2e 00 c7 45 8a 65 00 78 00 c7 45 8e 65 00 20 00 c7 45 92 25 00 73 00 } //10
		$a_01_2 = {74 79 70 65 72 74 74 73 78 2e 63 6f 6d 3a 38 30 3b 74 79 70 69 63 61 6c 73 78 2e 63 6f 6d 3a 38 30 } //1 typerttsx.com:80;typicalsx.com:80
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=21
 
}