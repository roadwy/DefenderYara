
rule Trojan_Win32_Copak_KAO_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {31 30 01 db 81 c0 90 01 04 09 fb 09 ff 39 c8 75 dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}