
rule Trojan_Win32_Farfli_BAC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 65 f8 00 83 45 f8 06 8a 45 14 8b 4d fc 8a d0 d2 e2 8b 4d 08 80 e2 c0 08 11 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}