
rule Trojan_Win64_Latrodectus_MA_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b c8 48 2b cb 0f b6 44 0c ?? 43 32 44 0b ?? 41 88 41 ?? 41 81 fa ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}