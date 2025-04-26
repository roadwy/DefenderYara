
rule Trojan_Win32_Sabsik_MO_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 10 8b 4d 98 33 4d ac 8b 55 c0 89 0a 68 b5 00 00 00 8d 45 dc 50 8d 8d ac fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}