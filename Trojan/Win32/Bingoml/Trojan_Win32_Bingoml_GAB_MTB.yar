
rule Trojan_Win32_Bingoml_GAB_MTB{
	meta:
		description = "Trojan:Win32/Bingoml.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {e5 f0 fc e7 c7 45 90 01 01 a7 ea e7 89 33 c0 80 74 05 ec 89 40 83 f8 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}