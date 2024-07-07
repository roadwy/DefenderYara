
rule Trojan_Win32_CryptInject_YAA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 33 db 66 90 01 06 6c 00 c6 90 01 04 00 6b c7 05 90 01 08 c7 05 90 01 08 66 c7 05 90 01 06 c7 05 90 01 08 c7 05 90 01 08 c7 05 90 01 08 c6 05 90 01 05 c6 05 90 01 05 c6 05 90 01 05 c7 05 90 01 08 c7 05 90 01 08 c7 05 90 01 08 66 c7 05 90 01 06 88 90 01 05 56 3d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}