
rule Trojan_Win32_RedCap_SPH_MTB{
	meta:
		description = "Trojan:Win32/RedCap.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 45 f4 47 c6 45 f5 45 c6 45 f6 54 c6 45 f7 47 c6 45 f8 4f c6 45 f9 44 ff 15 90 01 04 5f 5b 85 c0 7f 90 00 } //1
		$a_01_1 = {31 30 33 2e 35 39 2e 31 31 33 2e 33 33 } //1 103.59.113.33
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}