
rule Trojan_Win32_Fragtor_AM_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 6a 00 6a 01 68 58 2a 47 00 ff 15 64 c1 45 00 8b d8 89 5d dc 85 db 0f 84 89 01 00 00 6a 00 68 00 01 00 80 6a 00 6a 00 68 80 2e 47 00 53 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}