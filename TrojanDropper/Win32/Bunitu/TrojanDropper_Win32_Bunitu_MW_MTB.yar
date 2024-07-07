
rule TrojanDropper_Win32_Bunitu_MW_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 da 8b 45 90 01 01 0f be 08 2b ca 8b 55 90 1b 00 88 0a 5e 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}