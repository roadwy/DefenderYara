
rule Ransom_MSIL_Nitro_MVT_MTB{
	meta:
		description = "Ransom:MSIL/Nitro.MVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {4e 69 74 72 6f 52 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //5 NitroRansomware.exe
		$a_80_1 = {57 68 79 20 61 72 65 20 62 6c 61 63 6b 20 62 6c 61 63 6b } //Why are black black  1
		$a_00_2 = {64 35 65 38 37 34 33 39 2d 32 31 65 36 2d 34 35 36 37 2d 61 38 37 37 2d 36 61 64 39 62 65 65 30 30 64 63 39 } //1 d5e87439-21e6-4567-a877-6ad9bee00dc9
	condition:
		((#a_00_0  & 1)*5+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1) >=6
 
}