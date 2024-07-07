
rule Trojan_Win32_StealC_SPI_MTB{
	meta:
		description = "Trojan:Win32/StealC.SPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 d7 89 45 f8 8b 45 d0 01 45 f8 8b 45 f8 8d 4d 90 01 01 33 c2 8b 55 f4 33 d0 89 55 f4 e8 90 01 04 8b 45 e8 29 45 fc 4e 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}