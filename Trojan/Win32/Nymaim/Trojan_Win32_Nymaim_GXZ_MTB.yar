
rule Trojan_Win32_Nymaim_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {29 c0 13 1d 90 01 04 01 f8 b5 01 00 c5 83 db 90 01 01 18 35 90 01 04 81 1d 90 01 04 b2 00 00 00 29 fb 19 ca 0b 0d 90 01 04 6a 00 81 34 24 90 01 04 8d 05 90 01 04 40 50 8d 05 90 01 04 40 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}