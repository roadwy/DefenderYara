
rule Trojan_Win32_Zusy_AMBG_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0e 30 08 8a 08 8a 16 02 d1 88 10 40 46 4f 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}