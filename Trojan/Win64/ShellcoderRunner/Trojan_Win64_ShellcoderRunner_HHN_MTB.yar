
rule Trojan_Win64_ShellcoderRunner_HHN_MTB{
	meta:
		description = "Trojan:Win64/ShellcoderRunner.HHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c8 83 c8 e0 ff c0 48 98 ff c1 42 0f b6 04 00 30 02 48 ff c2 48 63 c1 48 3b c7 72 d9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}