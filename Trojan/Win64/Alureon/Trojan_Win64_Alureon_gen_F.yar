
rule Trojan_Win64_Alureon_gen_F{
	meta:
		description = "Trojan:Win64/Alureon.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b9 00 02 00 00 b2 28 44 89 64 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b8 53 44 00 00 66 39 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}