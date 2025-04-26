
rule Backdoor_BAT_DCRat_SP_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 0b 00 00 0a 0a 06 28 ?? ?? ?? 0a 03 50 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 0f 00 00 0a 0c 08 07 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 02 50 16 02 50 } //2
		$a_01_1 = {63 4d 44 54 4d 2e 70 64 62 } //1 cMDTM.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}