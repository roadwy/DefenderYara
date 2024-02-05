
rule Ransom_Win32_Ragnarok_PD_MTB{
	meta:
		description = "Ransom:Win32/Ragnarok.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 fb 8b da 8b 95 f8 90 02 04 0f b6 84 1d 90 01 04 88 84 15 90 01 04 88 8c 1d 90 01 04 b9 06 00 00 00 0f b6 84 15 90 01 04 33 d2 03 c6 f7 f1 0f b6 84 15 90 01 04 30 87 90 01 04 47 8b 85 f8 90 02 04 81 ff a6 10 00 00 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}