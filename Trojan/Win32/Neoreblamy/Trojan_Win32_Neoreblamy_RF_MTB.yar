
rule Trojan_Win32_Neoreblamy_RF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 f8 00 00 00 68 db 19 00 00 68 fd 2a 00 00 68 09 49 00 00 6a 01 6a 00 ff 75 8c ff 75 88 68 aa 22 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}