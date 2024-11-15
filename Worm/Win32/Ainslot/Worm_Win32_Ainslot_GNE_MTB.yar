
rule Worm_Win32_Ainslot_GNE_MTB{
	meta:
		description = "Worm:Win32/Ainslot.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 67 32 00 4c c0 4b ?? ?? 4f 40 00 10 4f 40 00 40 ?? 0a 00 } //5
		$a_03_1 = {40 00 10 3e 32 00 30 4f ?? 00 03 00 03 00 d3 1d } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}