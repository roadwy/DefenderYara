
rule Trojan_Win32_Copak_SPDT_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 1a 01 c1 21 c0 89 f8 81 e3 ff 00 00 00 41 81 c7 f0 ec 13 20 31 1e 29 f9 81 e8 a9 ed 2c a8 81 c6 01 00 00 00 01 f8 09 c9 f7 d0 42 81 c7 01 00 00 00 21 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}