
rule Trojan_Win32_Tnega_AA_MTB{
	meta:
		description = "Trojan:Win32/Tnega.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 83 c4 04 81 c0 90 01 04 e8 90 01 04 31 17 89 c9 47 81 e9 90 01 04 83 ec 04 89 0c 24 58 39 f7 75 cf 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}