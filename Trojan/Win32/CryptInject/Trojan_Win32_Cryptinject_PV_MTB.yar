
rule Trojan_Win32_Cryptinject_PV_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {69 c9 ac 44 01 00 2b 0d 90 01 04 89 0d 90 01 04 8b 8c 02 aa df ff ff 81 c1 a8 07 04 01 89 0d 90 01 04 89 8c 02 aa df ff ff 83 c0 04 3d 4e 21 00 00 72 90 09 0d 00 0f b6 0d 90 01 04 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}