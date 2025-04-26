
rule Trojan_Win32_Lokibot_K_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d0 fc b9 ?? ?? ?? ?? 89 c7 90 05 15 02 31 db f3 a4 90 05 15 02 31 db bb ?? ?? ?? ?? 31 1c 08 83 c1 03 41 81 f9 ?? ?? ?? ?? 75 f1 ff e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}