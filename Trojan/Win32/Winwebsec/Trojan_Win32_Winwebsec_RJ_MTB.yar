
rule Trojan_Win32_Winwebsec_RJ_MTB{
	meta:
		description = "Trojan:Win32/Winwebsec.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 81 e1 ff ff 00 00 ba 01 00 00 00 d3 e2 8b 45 fc 89 50 20 8b 4d f8 81 e1 ff ff 00 00 83 f9 18 74 25 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}