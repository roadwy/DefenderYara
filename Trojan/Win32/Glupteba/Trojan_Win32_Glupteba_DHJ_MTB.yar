
rule Trojan_Win32_Glupteba_DHJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {3b fe 7c 0b e8 90 01 04 30 04 1f 4f 79 f5 8b 4d fc 5f 5e 33 cd 90 00 } //01 00 
		$a_02_1 = {0f b6 cb 03 c1 8b 4d fc 5f 25 ff 00 00 00 8a 80 90 01 04 5e 33 cd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}