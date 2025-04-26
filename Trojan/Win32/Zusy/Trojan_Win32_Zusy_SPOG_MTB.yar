
rule Trojan_Win32_Zusy_SPOG_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SPOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 c0 2e 69 64 61 74 61 20 20 00 20 00 00 00 80 00 00 00 02 00 00 00 36 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 63 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}