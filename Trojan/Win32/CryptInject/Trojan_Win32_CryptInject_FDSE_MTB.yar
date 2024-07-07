
rule Trojan_Win32_CryptInject_FDSE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.FDSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {2c 30 82 54 d9 d9 6d ed f2 32 30 12 28 2c ae 24 16 } //1
		$a_01_1 = {33 10 8b 5d ec b1 9f ee 20 7f 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}