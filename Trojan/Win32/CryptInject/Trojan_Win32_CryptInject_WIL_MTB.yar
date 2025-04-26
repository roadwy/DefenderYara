
rule Trojan_Win32_CryptInject_WIL_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.WIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f8 8d 5a 02 8b cb 66 0f be 02 66 31 01 8d 49 02 83 ef 01 75 f1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}