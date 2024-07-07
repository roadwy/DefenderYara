
rule Trojan_Win32_CryptInject_YR_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {dd d8 c6 05 90 01 03 00 65 c6 05 90 01 03 00 6c c6 05 90 01 03 00 2e c6 05 90 01 03 00 6e c6 05 90 01 03 00 33 c6 05 90 01 03 00 65 c6 05 90 01 03 00 6c c6 05 90 01 03 00 64 c6 05 90 01 03 00 6c c6 05 90 01 03 00 32 c6 05 90 01 03 00 72 c6 05 90 01 03 00 6b c6 05 90 01 03 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}