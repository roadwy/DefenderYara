
rule Trojan_Win32_Emotet_DDR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 08 8b 54 24 0c 8b c1 f7 d0 8b f2 f7 d6 0b c6 0b ca 23 c1 5e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}