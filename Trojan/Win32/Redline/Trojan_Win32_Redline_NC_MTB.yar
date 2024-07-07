
rule Trojan_Win32_Redline_NC_MTB{
	meta:
		description = "Trojan:Win32/Redline.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 86 c8 61 ff 4d 90 01 01 8b 45 90 01 01 0f 85 90 01 04 90 0a 41 00 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 33 c8 89 4d 90 01 01 8b 45 90 01 01 29 45 90 01 01 81 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}