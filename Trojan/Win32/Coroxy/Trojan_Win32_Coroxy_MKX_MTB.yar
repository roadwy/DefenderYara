
rule Trojan_Win32_Coroxy_MKX_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.MKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 c2 36 8a 8c 28 80 fe ff ff 36 88 8c 2b 80 fe ff ff 36 88 94 28 80 fe ff ff 02 ca 36 8a 8c 29 80 fe ff ff 30 0e 46 4f 0b ff 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}