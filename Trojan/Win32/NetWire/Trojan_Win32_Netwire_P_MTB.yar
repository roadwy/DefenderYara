
rule Trojan_Win32_Netwire_P_MTB{
	meta:
		description = "Trojan:Win32/Netwire.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5f 32 c0 5e 8b 8c 24 90 01 04 33 cc e8 90 01 04 81 c4 90 01 04 c3 8b ce 8d 51 01 90 00 } //01 00 
		$a_01_1 = {90 8a 01 41 84 c0 75 f9 2b ca 8d 79 0a 81 ff 00 02 } //00 00 
	condition:
		any of ($a_*)
 
}