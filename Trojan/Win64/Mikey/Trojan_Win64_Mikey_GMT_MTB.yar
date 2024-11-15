
rule Trojan_Win64_Mikey_GMT_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 4e 95 8c 62 45 03 87 ?? ?? ?? ?? 32 fd 2d } //5
		$a_03_1 = {8e 04 73 19 a4 74 ?? ?? ?? ?? d0 31 2e e7 6d e2 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}