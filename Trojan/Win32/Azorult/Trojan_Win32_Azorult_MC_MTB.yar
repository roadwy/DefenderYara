
rule Trojan_Win32_Azorult_MC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {33 c0 33 d2 8d 4c 24 18 51 66 89 54 24 18 66 89 44 24 1a 8b 54 24 18 52 50 } //5
		$a_02_1 = {50 6a 00 ff d6 6a 00 8d 8c 24 ?? ?? ?? ?? 51 ff d7 8d 54 24 ?? 52 ff d3 6a 00 ff d5 6a 00 8d 84 24 } //5
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*5) >=10
 
}