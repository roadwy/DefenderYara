
rule Trojan_Win32_Emotet_D_MTB{
	meta:
		description = "Trojan:Win32/Emotet.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 4a 0d ce 09 90 02 10 e8 90 01 02 ff ff 90 02 10 e8 90 01 02 ff ff 90 08 00 08 6a 40 68 00 10 00 00 90 02 10 ff d0 90 02 10 e8 90 01 02 00 00 90 02 10 68 91 01 00 00 50 e8 90 01 02 ff ff 83 c4 18 83 78 90 01 01 08 72 90 00 } //01 00 
		$a_02_1 = {68 4a 0d ce 09 90 02 10 e8 90 01 02 ff ff 90 02 10 e8 90 01 02 ff ff 90 08 00 08 6a 40 68 00 10 00 00 90 02 10 ff 55 90 02 10 e8 90 01 02 00 00 90 02 10 68 91 01 00 00 50 e8 90 01 02 ff ff 83 c4 18 83 78 90 01 01 08 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}