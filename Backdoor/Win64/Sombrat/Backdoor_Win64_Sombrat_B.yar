
rule Backdoor_Win64_Sombrat_B{
	meta:
		description = "Backdoor:Win64/Sombrat.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af c8 89 d3 80 f3 ae 80 f2 51 f6 c1 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}