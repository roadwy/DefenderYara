
rule Trojan_Win32_Ursnif_XB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.XB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 8a 24 0a 34 ff 00 c4 88 24 0e 5e 5d } //00 00 
	condition:
		any of ($a_*)
 
}