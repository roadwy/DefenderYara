
rule Trojan_Win32_CryptInject_CCJU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 31 cb 89 da 88 10 83 45 ec 01 8b 45 ?? ?? 45 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}