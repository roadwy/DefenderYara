
rule Trojan_Win32_Delfinject_RWB_MTB{
	meta:
		description = "Trojan:Win32/Delfinject.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f6 c7 f0 74 90 01 01 8b 45 90 01 01 8b 40 90 01 01 8b 75 90 01 01 8b 76 90 01 01 03 06 66 81 e3 ff 0f 0f b7 db 03 c3 8b 5d 90 01 01 8b 5b 90 01 01 01 18 83 01 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}