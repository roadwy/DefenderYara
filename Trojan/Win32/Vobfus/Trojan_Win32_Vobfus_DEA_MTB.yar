
rule Trojan_Win32_Vobfus_DEA_MTB{
	meta:
		description = "Trojan:Win32/Vobfus.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c3 d3 e0 03 fb c1 eb 05 03 9d 90 01 01 fd ff ff 03 85 90 01 01 fd ff ff 89 bd 90 01 01 fd ff ff 89 45 f8 8b 85 90 01 01 fd ff ff 31 45 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}