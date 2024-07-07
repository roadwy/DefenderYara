
rule Trojan_Win32_Emotet_RPO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RPO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 4d 0c ac 31 ff 89 d7 81 e7 ff 00 00 00 30 c3 c1 ea 08 81 e2 ff ff ff 00 b9 08 00 00 00 d1 ef 73 06 81 f7 20 83 b8 ed e2 f4 31 fa eb cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}