
rule Trojan_Win32_Remcos_AN_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7b 0c 8b ce e8 a5 ff ff ff 8b cb 8b f0 e8 9c ff ff ff 8b 4d fc 33 f0 23 f1 31 34 97 42 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}