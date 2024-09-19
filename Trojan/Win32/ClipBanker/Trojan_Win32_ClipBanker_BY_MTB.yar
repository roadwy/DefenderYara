
rule Trojan_Win32_ClipBanker_BY_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 0f be 54 ?? ?? 8b 45 08 03 45 ?? 0f be 08 33 ca 8b 55 ?? 03 55 fc 88 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}