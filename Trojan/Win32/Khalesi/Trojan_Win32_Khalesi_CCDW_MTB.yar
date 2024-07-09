
rule Trojan_Win32_Khalesi_CCDW_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.CCDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 17 29 ce 81 c7 ?? ?? ?? ?? 39 c7 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}