
rule Trojan_Win32_Tinba_AMMC_MTB{
	meta:
		description = "Trojan:Win32/Tinba.AMMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 ce 30 f2 88 55 c7 8b 4d d4 8b 75 b0 29 f0 } //2
		$a_01_1 = {88 1a 8b 55 d4 8b 75 c0 8b 7d c0 31 cf 89 7d c0 21 c6 89 75 c0 8b 45 ac 01 c2 89 55 d4 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}