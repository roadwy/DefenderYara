
rule Trojan_Win32_Emotet_PVM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {b9 7c 03 00 00 f7 f9 8a 5d 00 8b 44 24 14 83 c0 f0 c7 84 24 90 01 04 ff ff ff ff 8d 48 0c 8a 54 14 18 32 da 88 5d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}