
rule Trojan_Win32_CryptInject_GTLM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.GTLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 8a 1c 0a 33 d2 f7 f7 8b 45 90 01 01 8a 04 02 32 c3 88 01 0f be c3 c1 f8 90 01 01 83 e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}