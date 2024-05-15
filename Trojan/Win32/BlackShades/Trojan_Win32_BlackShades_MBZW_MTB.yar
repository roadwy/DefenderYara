
rule Trojan_Win32_BlackShades_MBZW_MTB{
	meta:
		description = "Trojan:Win32/BlackShades.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 d0 30 42 00 b8 31 42 00 f0 2a 42 00 } //01 00 
		$a_01_1 = {2b 40 00 a4 12 40 00 40 f0 34 00 00 ff ff ff 08 } //00 00 
	condition:
		any of ($a_*)
 
}