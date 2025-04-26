
rule Trojan_Win32_Lazy_ALZY_MTB{
	meta:
		description = "Trojan:Win32/Lazy.ALZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 56 ff 74 88 fc 53 57 ff 15 2c d0 43 00 6a 00 6a 00 53 ff 35 34 d0 43 00 6a 00 6a 00 57 ff 15 24 d0 43 00 8b f0 68 10 27 00 00 56 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}