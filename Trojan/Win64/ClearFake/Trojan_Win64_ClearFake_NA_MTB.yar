
rule Trojan_Win64_ClearFake_NA_MTB{
	meta:
		description = "Trojan:Win64/ClearFake.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {cc cc cc cc cc cc 48 83 fe 00 75 01 c3 44 30 27 48 8d 05 ?? ?? 00 00 } //5
		$a_03_1 = {cc cc cc 48 ff c7 48 ff ce e9 ?? ?? ff ff } //3
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*3) >=8
 
}