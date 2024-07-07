
rule Trojan_Win32_Doina_CCIA_MTB{
	meta:
		description = "Trojan:Win32/Doina.CCIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 8b 45 f8 8b 48 24 51 8b 55 f8 8b 42 30 50 8b 4d f0 51 ff 55 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}