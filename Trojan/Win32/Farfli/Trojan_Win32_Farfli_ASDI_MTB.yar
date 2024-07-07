
rule Trojan_Win32_Farfli_ASDI_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b cf 8a 14 01 80 f2 62 88 10 40 4e 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}