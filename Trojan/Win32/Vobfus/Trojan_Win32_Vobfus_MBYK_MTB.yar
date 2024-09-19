
rule Trojan_Win32_Vobfus_MBYK_MTB{
	meta:
		description = "Trojan:Win32/Vobfus.MBYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f8 26 40 00 d8 15 40 00 10 f1 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 01 00 e9 00 00 00 30 12 40 00 c8 13 40 00 70 11 40 00 78 00 00 00 7f 00 00 00 89 00 00 00 8a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}