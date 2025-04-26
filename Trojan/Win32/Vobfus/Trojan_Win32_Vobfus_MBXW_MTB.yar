
rule Trojan_Win32_Vobfus_MBXW_MTB{
	meta:
		description = "Trojan:Win32/Vobfus.MBXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {60 2f 41 00 2c 39 40 00 12 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 01 00 e9 00 00 00 00 37 40 00 e4 37 40 00 74 36 40 00 78 00 00 00 81 00 00 00 8a 00 00 00 8b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}