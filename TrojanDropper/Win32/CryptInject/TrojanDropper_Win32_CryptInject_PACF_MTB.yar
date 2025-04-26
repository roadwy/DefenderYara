
rule TrojanDropper_Win32_CryptInject_PACF_MTB{
	meta:
		description = "TrojanDropper:Win32/CryptInject.PACF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 0c 90 40 00 8d 7e 01 ba 1c f8 47 00 8a 44 38 ff 8a 54 1a ff 30 c2 8b 7d c0 8d 04 37 88 10 39 f1 77 cb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}