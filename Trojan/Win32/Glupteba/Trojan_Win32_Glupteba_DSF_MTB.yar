
rule Trojan_Win32_Glupteba_DSF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 45 90 01 01 8c eb 73 22 8b 90 00 } //01 00 
		$a_02_1 = {c1 e9 05 03 8d 90 01 02 ff ff 03 90 01 03 ff ff 89 90 01 05 33 90 01 01 8b 8d 90 01 02 ff ff 03 90 01 01 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}