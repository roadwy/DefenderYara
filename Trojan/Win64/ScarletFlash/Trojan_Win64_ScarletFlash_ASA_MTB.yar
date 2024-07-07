
rule Trojan_Win64_ScarletFlash_ASA_MTB{
	meta:
		description = "Trojan:Win64/ScarletFlash.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 33 c9 48 8d 15 fa 04 0d 00 41 83 c8 ff 48 8d 0d e7 04 0d 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}