
rule Trojan_Win32_Glupteba_SPD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {89 45 ec 33 45 e4 31 45 fc 8b 45 fc 29 45 f4 } //00 00 
	condition:
		any of ($a_*)
 
}