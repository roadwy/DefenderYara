
rule Trojan_Win32_SpyEyes_TA_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.TA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d2 fb 66 41 d3 cb 66 44 23 d8 44 31 2c 24 f9 41 5b 4d 63 ed f5 4d 03 c5 e9 } //1
		$a_01_1 = {ed 4f 30 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}