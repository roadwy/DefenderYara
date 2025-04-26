
rule Trojan_Win32_Copak_BB_MTB{
	meta:
		description = "Trojan:Win32/Copak.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 17 4e 81 e9 c1 f2 71 2b 81 c7 04 00 00 00 81 c1 5d 6c 85 cb 39 df 75 e2 } //3
		$a_01_1 = {31 3a 81 eb eb f7 9a c4 81 c2 04 00 00 00 89 db 09 d9 39 c2 75 e5 } //3
		$a_01_2 = {89 ff 09 ff 46 89 f8 89 f8 81 fe 84 27 00 01 75 bd } //2
		$a_01_3 = {81 c6 01 00 00 00 81 c3 36 d5 b8 e3 21 c9 21 cb 81 fe ec 56 00 01 75 c0 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=5
 
}