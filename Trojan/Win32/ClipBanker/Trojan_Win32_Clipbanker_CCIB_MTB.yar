
rule Trojan_Win32_Clipbanker_CCIB_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.CCIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 40 23 40 00 33 ff 6a 01 57 89 7d fc ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}