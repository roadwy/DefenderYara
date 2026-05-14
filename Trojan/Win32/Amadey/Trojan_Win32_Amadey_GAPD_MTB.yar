
rule Trojan_Win32_Amadey_GAPD_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GAPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00 dd b6 42 53 99 d7 2c 00 99 d7 2c 00 99 d7 2c 00 8d bc 2f 01 94 d7 2c 00 8d bc 29 01 23 d7 2c 00 cb a2 28 01 8b d7 2c 00 cb a2 2f 01 8f d7 2c } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}