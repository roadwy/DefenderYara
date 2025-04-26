
rule Trojan_Win32_Zusy_EAKJ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EAKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d8 88 5d fc 8b 45 e8 03 45 f4 8a 4d fc 88 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}