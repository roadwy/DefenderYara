
rule Trojan_Win32_Gepys_RPK_MTB{
	meta:
		description = "Trojan:Win32/Gepys.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f af 4d 10 29 ca 03 55 08 ff 4d f0 8a 0a 88 4d db 8a 08 88 0a 8a 55 db 88 10 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gepys_RPK_MTB_2{
	meta:
		description = "Trojan:Win32/Gepys.RPK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 c1 31 df 03 7d 08 ff 4d f0 8a 07 88 45 cb 8a 01 88 07 8a 45 cb 88 01 8b 55 cc } //00 00 
	condition:
		any of ($a_*)
 
}