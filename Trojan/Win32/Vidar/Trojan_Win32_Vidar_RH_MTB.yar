
rule Trojan_Win32_Vidar_RH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 6a 40 68 00 30 00 00 ff 70 50 56 ff 15 90 01 04 8b f0 85 f6 75 26 85 db 0f 84 9c 02 00 00 8b 45 fc 6a 40 68 00 30 00 00 ff 70 50 56 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}