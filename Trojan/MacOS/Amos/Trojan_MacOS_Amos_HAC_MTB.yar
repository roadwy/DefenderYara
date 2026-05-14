
rule Trojan_MacOS_Amos_HAC_MTB{
	meta:
		description = "Trojan:MacOS/Amos.HAC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 cf 83 e7 07 40 8a bc 3c ?? ?? ?? ?? 40 30 7c 31 10 48 d1 c8 48 89 84 24 90 1b 00 48 ff c1 48 39 ca 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}