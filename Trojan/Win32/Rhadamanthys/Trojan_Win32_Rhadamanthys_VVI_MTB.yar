
rule Trojan_Win32_Rhadamanthys_VVI_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.VVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 8b 4d 10 83 c4 0c 2b c8 89 5d 90 01 01 8a 14 06 32 10 88 14 01 40 ff 4d fc 75 90 01 01 53 8d 45 ec 50 ff 75 08 e8 90 01 04 01 5d 0c 01 5d 10 83 c4 0c 2b f3 4f 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}