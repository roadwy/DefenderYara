
rule Backdoor_Win32_Lotok_KAA_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ac 51 59 49 32 06 88 07 83 c6 01 83 c7 01 49 85 c9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}