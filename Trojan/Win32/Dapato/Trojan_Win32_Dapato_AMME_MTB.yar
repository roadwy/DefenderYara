
rule Trojan_Win32_Dapato_AMME_MTB{
	meta:
		description = "Trojan:Win32/Dapato.AMME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 6a 00 8d 85 bc fb ff ff 50 ff 15 90 01 04 85 c0 74 0f 6a 02 8d 85 bc fb ff ff 50 ff 15 90 00 } //01 00 
		$a_01_1 = {25 00 73 00 5c 00 79 00 74 00 6f 00 6f 00 6c 00 } //00 00  %s\ytool
	condition:
		any of ($a_*)
 
}