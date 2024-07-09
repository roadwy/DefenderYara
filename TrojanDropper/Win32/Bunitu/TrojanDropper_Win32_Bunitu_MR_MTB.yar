
rule TrojanDropper_Win32_Bunitu_MR_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5e 8b e5 5d c3 90 0a 1e 00 03 05 ?? ?? ?? ?? 0f be ?? 30 f7 ?? 8b ?? f8 0f be ?? 2b ?? 8b ?? f8 88 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}