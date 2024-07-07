
rule Backdoor_Win64_RomComLoader_C{
	meta:
		description = "Backdoor:Win64/RomComLoader.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 8b c1 48 d3 e8 42 32 44 04 50 42 88 44 05 38 83 c1 08 41 03 d4 4d 03 c4 83 f9 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}