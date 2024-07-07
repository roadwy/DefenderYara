
rule Trojan_Win32_Lazy_GPB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 8a 45 0c 8a 4d 08 c7 05 30 a5 20 10 ad 0b 00 00 c7 05 2c a5 20 10 39 14 00 00 30 c8 0f b6 c0 5d c3 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}