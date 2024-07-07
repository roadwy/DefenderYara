
rule PWS_Win32_Zbot_UU{
	meta:
		description = "PWS:Win32/Zbot.UU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 81 c0 fe ff ff ff 90 02 0a 38 10 90 03 01 01 75 74 90 02 0a 8b 90 03 01 01 3c 34 24 90 02 0a 90 03 01 01 57 56 59 49 68 90 01 05 c1 90 02 08 36 39 90 03 01 01 31 39 74 90 02 08 eb 90 02 05 ff d1 90 09 4a 00 90 02 15 68 90 01 04 5a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}