
rule Trojan_Win32_Lazy_GTS_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 d1 32 c3 81 d9 ?? ?? ?? ?? f6 d8 2c 04 d0 c0 03 ce f6 d1 8b cf } //5
		$a_01_1 = {3b d6 32 d9 3b e2 88 04 0c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}