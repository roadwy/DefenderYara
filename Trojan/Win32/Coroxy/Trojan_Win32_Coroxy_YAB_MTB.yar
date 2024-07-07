
rule Trojan_Win32_Coroxy_YAB_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 90 01 04 03 d8 8b 45 d8 31 18 83 45 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}