
rule Trojan_Win32_CryptInject_SS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff 89 45 f4 90 05 10 01 90 33 c0 90 05 10 01 90 8b d0 90 05 10 01 90 8b 5d f4 90 05 10 01 90 03 da 90 05 10 01 90 8b d0 90 05 10 01 90 8b f3 90 05 10 01 90 8a 92 90 01 03 00 88 55 fb 90 05 10 01 90 b2 90 01 01 90 05 10 01 90 32 55 fb 90 05 10 01 90 88 16 90 05 10 01 90 40 3d 90 01 01 00 00 75 90 00 } //1
		$a_02_1 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 05 10 01 90 8b 7d fc ff 75 f8 01 3c 24 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}