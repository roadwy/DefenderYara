
rule Trojan_Win32_Qukart_GAD_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f8 f7 e7 89 45 fc 89 c7 8b 45 0c 3d 00 01 00 00 0f 85 ?? ?? ?? ?? 89 f8 31 f8 89 c7 83 7d 10 09 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}