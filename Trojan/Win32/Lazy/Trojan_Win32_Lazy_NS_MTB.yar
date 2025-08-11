
rule Trojan_Win32_Lazy_NS_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {a1 04 d0 40 00 56 85 c0 be 04 d0 40 00 74 17 8b 0d 00 d0 40 00 6a 00 51 6a 01 ff d0 8b 46 04 83 c6 04 85 c0 75 e9 } //2
		$a_01_1 = {a1 40 dc 40 00 5e 85 c0 74 02 ff e0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}