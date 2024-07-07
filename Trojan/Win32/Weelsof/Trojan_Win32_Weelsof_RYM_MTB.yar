
rule Trojan_Win32_Weelsof_RYM_MTB{
	meta:
		description = "Trojan:Win32/Weelsof.RYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 fe e6 77 00 00 eb 90 0a 84 00 8a 1c 30 90 02 1f 80 f3 90 01 01 eb 90 02 1f f6 d3 eb 90 02 1f 80 f3 90 01 01 eb 90 02 25 88 1c 30 90 02 1f 46 eb 90 00 } //1
		$a_03_1 = {81 ff e6 77 00 00 90 02 1f eb 90 0a 8f 00 8a 1c 38 90 90 90 02 1f eb 90 02 1f 80 f3 90 02 1f f6 d3 90 02 1f 80 f3 90 02 1f 88 1c 38 90 90 90 02 1f 47 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}