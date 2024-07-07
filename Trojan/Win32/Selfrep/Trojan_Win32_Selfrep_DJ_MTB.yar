
rule Trojan_Win32_Selfrep_DJ_MTB{
	meta:
		description = "Trojan:Win32/Selfrep.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 55 ec 83 c2 01 89 55 ec 81 7d ec 10 27 00 00 73 19 e8 90 01 04 99 b9 ff 00 00 00 f7 f9 8b 45 ec 88 94 05 90 01 04 eb d5 90 00 } //1
		$a_03_1 = {8b 55 d0 83 c2 01 89 55 d0 81 7d d0 90 01 04 73 19 e8 90 01 04 99 b9 ff 00 00 00 f7 f9 8b 45 d0 88 94 05 90 01 04 eb d5 90 00 } //1
		$a_03_2 = {81 c2 20 a1 07 00 89 55 a8 6a 00 8d 55 c0 52 8b 45 a8 50 8d 8d 90 01 04 51 8b 55 f0 52 ff 15 90 00 } //5
		$a_01_3 = {69 48 18 fd 43 03 00 81 c1 c3 9e 26 00 89 48 18 c1 e9 10 81 e1 ff 7f 00 00 8b c1 } //5
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*5+(#a_01_3  & 1)*5) >=11
 
}