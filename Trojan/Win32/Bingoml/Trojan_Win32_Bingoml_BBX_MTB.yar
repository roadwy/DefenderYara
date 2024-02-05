
rule Trojan_Win32_Bingoml_BBX_MTB{
	meta:
		description = "Trojan:Win32/Bingoml.BBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 01 8d 04 0e 83 e0 0f 0f b6 80 90 01 04 30 41 01 8d 04 0f 83 e0 0f 0f b6 80 90 01 04 30 41 02 8d 04 0b 83 e0 0f 8d 49 04 0f b6 80 90 01 04 30 41 ff 81 fa 00 42 01 00 72 b4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}