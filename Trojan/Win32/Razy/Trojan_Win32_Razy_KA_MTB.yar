
rule Trojan_Win32_Razy_KA_MTB{
	meta:
		description = "Trojan:Win32/Razy.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0b 01 f6 09 f0 81 e1 90 01 04 81 e8 90 01 04 21 d2 31 0f 21 c2 81 c0 90 01 04 40 47 89 f0 ba 90 01 04 21 d2 81 c3 90 01 04 f7 d6 29 d0 81 ff 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}