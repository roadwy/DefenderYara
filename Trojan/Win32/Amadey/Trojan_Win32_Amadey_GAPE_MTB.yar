
rule Trojan_Win32_Amadey_GAPE_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GAPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 53 92 d7 2c 00 92 d7 2c 00 92 d7 2c 00 86 bc 2f 01 9f d7 2c 00 86 bc 29 01 28 d7 2c 00 c0 a2 28 01 80 d7 2c 00 c0 a2 2f 01 84 d7 2c 00 c0 a2 29 01 cb d7 2c 00 a3 8b d1 00 90 d7 2c } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}