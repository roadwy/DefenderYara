
rule Trojan_Win32_ClipBanker_FAA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.FAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 08 33 ca 8b 55 08 03 55 f8 88 0a eb ?? 8b 45 08 03 45 f8 0f be 08 f7 d1 8b 55 08 03 55 f8 88 0a } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}