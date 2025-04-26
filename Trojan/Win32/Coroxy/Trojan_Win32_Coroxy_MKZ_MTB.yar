
rule Trojan_Win32_Coroxy_MKZ_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe c3 36 8a 94 2b 00 fc ff ff 02 c2 36 8a 8c 28 00 fc ff ff 36 88 8c 2b 00 fc ff ff 36 88 94 28 00 fc ff ff 02 ca 36 8a 8c 29 00 fc ff ff 30 0e 46 4f 75 cc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}