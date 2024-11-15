
rule Backdoor_Win64_Cobeacon_ARAX_MTB{
	meta:
		description = "Backdoor:Win64/Cobeacon.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 80 30 77 4d 8d 40 01 41 ff c1 48 8d 45 ?? 48 8b ?? 48 ff [0-05] 75 f7 49 63 c1 48 3b c1 72 dd } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}