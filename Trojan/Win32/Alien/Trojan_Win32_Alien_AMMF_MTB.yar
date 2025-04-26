
rule Trojan_Win32_Alien_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Alien.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1b ca c6 bb c5 b6 a2 32 c6 25 e5 48 8e b2 8b fb 76 42 35 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}