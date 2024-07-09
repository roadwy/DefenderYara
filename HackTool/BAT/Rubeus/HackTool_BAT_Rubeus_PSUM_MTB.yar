
rule HackTool_BAT_Rubeus_PSUM_MTB{
	meta:
		description = "HackTool:BAT/Rubeus.PSUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 11 08 03 59 28 ?? 06 00 06 13 09 03 11 09 7b d4 02 00 04 58 10 01 11 07 11 09 6f ?? 01 00 0a 03 11 08 32 da } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}