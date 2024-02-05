
rule Trojan_Win32_Elzob_DSK_MTB{
	meta:
		description = "Trojan:Win32/Elzob.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 0f b6 96 30 21 40 00 03 c3 0f b6 08 33 ff 33 cf 47 81 ff ff 00 00 00 7c 90 01 01 32 ca 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}