
rule Ransom_Win32_Nokoyawa_MK_MTB{
	meta:
		description = "Ransom:Win32/Nokoyawa.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 8b 45 90 01 01 8a 14 10 8b 4d 90 01 01 8b 45 90 01 01 32 14 01 8b 4d 90 01 01 8b 45 90 01 01 88 14 08 ff 45 90 01 01 8b 55 90 01 01 3b 55 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}