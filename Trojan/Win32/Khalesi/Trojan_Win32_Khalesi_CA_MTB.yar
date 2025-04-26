
rule Trojan_Win32_Khalesi_CA_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d9 31 3e 01 db 21 cb 81 c6 01 00 00 00 39 c6 75 e3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}