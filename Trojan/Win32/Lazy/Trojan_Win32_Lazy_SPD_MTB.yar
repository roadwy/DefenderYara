
rule Trojan_Win32_Lazy_SPD_MTB{
	meta:
		description = "Trojan:Win32/Lazy.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 3e b8 ed 2b 90 0f 21 c1 ba 09 ff 66 12 81 e7 ff 00 00 00 48 09 c2 31 3b 42 21 c9 43 f7 d1 48 81 e9 c7 e3 6a f4 46 09 c8 f7 d1 4a } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}