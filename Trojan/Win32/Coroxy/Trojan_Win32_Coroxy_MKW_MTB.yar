
rule Trojan_Win32_Coroxy_MKW_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.MKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 3b 30 06 46 43 49 3b 5d 0c 75 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}