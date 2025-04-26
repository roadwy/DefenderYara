
rule Trojan_Win32_Vidar_VD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 45 10 33 d2 f7 f1 8b 45 0c 8a 0c 02 8b 45 10 8b 55 08 03 c3 32 0c 02 88 08 ff 75 fc ff d7 ff 75 fc ff d7 ff 75 fc ff d7 ff 75 fc ff d7 ff 45 10 39 75 10 72 ab } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}