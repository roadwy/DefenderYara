
rule Trojan_Win32_PonyStealer_EAOP_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.EAOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 ec 10 8b d4 89 3a 8b 3d e4 10 40 00 89 42 04 89 72 08 6a 02 89 4a 0c 8b 55 d4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}