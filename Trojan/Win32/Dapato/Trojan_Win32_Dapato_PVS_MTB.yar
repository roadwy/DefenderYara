
rule Trojan_Win32_Dapato_PVS_MTB{
	meta:
		description = "Trojan:Win32/Dapato.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8a 1c 28 30 1c 31 40 41 3b c7 7c 90 01 01 33 c0 3b ca 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}