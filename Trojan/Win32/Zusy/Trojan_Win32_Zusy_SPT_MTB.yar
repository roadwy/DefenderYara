
rule Trojan_Win32_Zusy_SPT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 95 9f fc ff ff 0f b6 85 9f fc ff ff 03 85 a0 fc ff ff 88 85 9f fc ff ff 0f b6 8d 9f fc ff ff c1 f9 02 0f b6 95 9f fc ff ff c1 e2 06 0b ca 88 8d 9f fc ff ff 0f b6 85 9f fc ff ff 83 c0 39 88 85 9f fc ff ff 8b 8d a0 fc ff ff 8a 95 9f fc ff ff 88 54 0d 8c e9 } //00 00 
	condition:
		any of ($a_*)
 
}