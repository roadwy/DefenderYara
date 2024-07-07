
rule Trojan_Win32_Coinminer_RPX_MTB{
	meta:
		description = "Trojan:Win32/Coinminer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c9 e8 33 00 00 00 4f 01 f9 31 06 01 ff 81 ef 90 01 04 46 b9 90 01 04 89 ff 39 de 75 db 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}