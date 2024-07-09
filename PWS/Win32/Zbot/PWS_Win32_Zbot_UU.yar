
rule PWS_Win32_Zbot_UU{
	meta:
		description = "PWS:Win32/Zbot.UU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 81 c0 fe ff ff ff [0-0a] 38 10 (75|74) [0-0a] 8b 90 03 01 01 3c 34 24 [0-0a] 90 03 01 01 57 56 59 49 68 ?? ?? ?? ?? ?? c1 [0-08] 36 39 90 03 01 01 31 39 74 [0-08] eb [0-05] ff d1 90 09 4a 00 [0-15] 68 ?? ?? ?? ?? 5a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}