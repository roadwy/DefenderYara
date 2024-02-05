
rule Trojan_Win32_MultiPlug_PVA_MTB{
	meta:
		description = "Trojan:Win32/MultiPlug.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {c7 85 3c ff ff ff c3 2f 51 48 c7 85 68 ff ff ff 1c e5 bb 64 c7 45 60 f1 85 f0 66 c7 45 e0 34 d1 53 63 c7 45 f0 07 d0 dc 4f c7 45 3c 03 cb be 53 90 09 0c 00 e8 90 01 04 c7 45 34 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}