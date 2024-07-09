
rule Trojan_Win32_CryptInject_MLS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c1 04 89 4d ?? c7 45 ec 0f 0d 00 00 c7 45 ec 0f 0d 00 00 e8 ?? ?? ?? ?? ba 39 00 00 00 85 d2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}