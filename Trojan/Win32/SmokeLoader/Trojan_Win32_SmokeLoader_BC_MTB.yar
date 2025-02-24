
rule Trojan_Win32_SmokeLoader_BC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 f8 8b cb c1 e1 04 03 4d dc 8d 14 18 33 ca 33 4d fc } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}