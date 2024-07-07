
rule Trojan_Win32_Ekstak_EK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 f5 ce 73 00 17 33 70 00 00 be 0a 00 d4 bd 14 99 c2 ec 6f 00 00 d4 00 00 95 b1 1d 1c } //1
		$a_01_1 = {2a 01 00 00 00 e7 e8 6d 00 09 4d 6a 00 00 be 0a 00 d4 bd 14 99 99 06 6a 00 00 d4 00 00 8b 03 dd e1 } //1
		$a_01_2 = {2a 01 00 00 00 5d 4d 71 00 cf b0 6d 00 00 c0 0a 00 0d 15 b6 76 82 89 6d 00 00 d4 00 00 9a 16 78 7d } //1
		$a_01_3 = {2a 01 00 00 00 e8 ab 70 00 0a 10 6d 00 00 be 0a 00 d4 bd 14 99 8f d3 6c 00 00 d4 00 00 2e 44 4a 98 } //1
		$a_01_4 = {2a 01 00 00 00 5d c8 71 00 7f 2c 6e 00 00 be 0a 00 d4 bd 14 99 4a 05 6e 00 00 d4 00 00 35 56 d3 b6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}