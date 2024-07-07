
rule Ransom_Win32_Gandcrab_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 30 80 f3 90 01 01 f6 d3 80 f3 90 01 01 88 1c 30 90 90 90 90 50 58 90 90 84 c0 46 84 c0 90 90 81 fe 90 01 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 75 d2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}