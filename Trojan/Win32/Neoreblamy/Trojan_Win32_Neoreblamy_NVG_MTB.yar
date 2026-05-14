
rule Trojan_Win32_Neoreblamy_NVG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 45 ec 83 c0 01 89 45 ec 83 7d ec 01 7d 10 8b 4d ec } //1
		$a_03_1 = {6b c2 00 8b 8c 05 ?? ?? ff ff 39 4d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}