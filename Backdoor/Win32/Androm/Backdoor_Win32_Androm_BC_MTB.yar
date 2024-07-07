
rule Backdoor_Win32_Androm_BC_MTB{
	meta:
		description = "Backdoor:Win32/Androm.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c6 f7 75 08 8a 0c 1a 30 0c 3e 46 3b 75 10 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}