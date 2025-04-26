
rule Trojan_Win32_CryptInject_YAW_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 fc 5b 83 65 fc 00 c6 45 fc 5d 83 65 fc 00 c6 45 fc 5f 83 65 fc 00 c6 45 fc 61 83 65 fc 00 c6 45 fc 63 } //1
		$a_01_1 = {8a 44 1e ff 84 c0 74 d0 30 04 1e eb cb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}