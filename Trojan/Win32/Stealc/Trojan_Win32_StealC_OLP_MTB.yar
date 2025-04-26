
rule Trojan_Win32_StealC_OLP_MTB{
	meta:
		description = "Trojan:Win32/StealC.OLP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 46 89 44 24 14 ?? 83 6c 24 ?? 46 8a 44 24 14 30 04 1f 47 3b fd 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}