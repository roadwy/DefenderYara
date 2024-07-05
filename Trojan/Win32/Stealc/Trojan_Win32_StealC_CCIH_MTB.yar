
rule Trojan_Win32_StealC_CCIH_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 0c 3a 8d 42 90 01 01 30 41 90 01 01 42 83 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}