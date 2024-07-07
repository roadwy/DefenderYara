
rule Trojan_Win32_CryptInject_AL_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d3 8b c7 e8 90 01 02 ff ff 43 81 fb 90 01 02 00 00 75 ee 90 00 } //1
		$a_02_1 = {8b c8 03 ca 90 05 10 01 90 b0 90 01 01 90 05 10 01 90 32 82 90 01 03 00 90 05 10 01 90 88 01 90 05 10 01 90 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}