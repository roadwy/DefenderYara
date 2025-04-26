
rule Trojan_Win32_Vidar_PAJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 d8 03 45 ac 03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ec 31 18 6a 00 e8 ?? ?? ?? ?? 8b 55 e8 83 c2 04 03 c2 89 45 e8 8b 45 ec 83 c0 04 89 45 ec } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}