
rule Trojan_Win32_Coroxy_YAA_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 5d cc 03 5d ac 03 5d e8 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 31 18 83 45 e8 04 83 45 d8 04 8b 45 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}