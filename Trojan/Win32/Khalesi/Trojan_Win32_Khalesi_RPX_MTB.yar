
rule Trojan_Win32_Khalesi_RPX_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 31 32 42 89 cf 01 cf 39 c2 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}