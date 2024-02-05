
rule Trojan_Win32_Razy_K_MTB{
	meta:
		description = "Trojan:Win32/Razy.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {ba e8 b4 52 2e 29 ca 31 38 40 09 c9 39 f0 75 dd } //00 00 
	condition:
		any of ($a_*)
 
}