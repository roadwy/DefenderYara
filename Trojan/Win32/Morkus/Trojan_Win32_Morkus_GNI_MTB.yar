
rule Trojan_Win32_Morkus_GNI_MTB{
	meta:
		description = "Trojan:Win32/Morkus.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 20 41 13 34 72 50 07 bc 90 01 04 17 3c f3 85 34 58 0b 7e 12 80 78 d6 0b d3 a3 90 01 04 2b f4 0f fd d4 0a 04 f2 2c 37 e7 7b 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}