
rule Trojan_Win32_Copak_GPAD_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 8a 43 00 [0-30] 31 [0-60] ff 00 00 00 [0-5f] 81 ?? f4 01 00 00 75 05 } //4
		$a_03_1 = {c1 b3 43 00 [0-30] 31 [0-60] ff 00 00 00 [0-5f] 81 ?? f4 01 00 00 75 05 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4) >=4
 
}