
rule Backdoor_Win64_Mozaakai_SD_MTB{
	meta:
		description = "Backdoor:Win64/Mozaakai.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 ca 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 41 ff c2 48 f7 e1 48 c1 ea ?? 48 8d 04 52 48 c1 e0 ?? 48 2b c8 49 2b cb 8a 44 0c ?? 42 32 04 0b 41 88 01 49 ff c1 45 3b d4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}