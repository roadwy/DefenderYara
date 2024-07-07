
rule Trojan_BAT_CryptInject_MKV_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 5f 07 00 0a 0a dd 20 00 00 00 26 72 3d 00 00 70 72 dc 00 00 70 28 60 07 00 0a 6f 61 07 00 0a 74 27 01 00 01 0a dd 00 00 00 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}