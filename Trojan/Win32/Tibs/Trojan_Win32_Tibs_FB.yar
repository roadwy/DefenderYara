
rule Trojan_Win32_Tibs_FB{
	meta:
		description = "Trojan:Win32/Tibs.FB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 cd ff 83 ed 90 01 01 89 ea 90 03 01 01 08 84 d2 75 03 83 c0 02 90 02 02 09 90 03 01 01 ed d5 75 90 01 01 bf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}