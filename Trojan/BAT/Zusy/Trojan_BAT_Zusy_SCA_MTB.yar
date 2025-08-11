
rule Trojan_BAT_Zusy_SCA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 24 07 06 07 06 93 02 7b ?? ?? ?? 04 04 20 2a e7 e5 12 20 7f e7 a6 fa 59 20 a4 ff 3e 18 61 5f 91 04 60 61 d1 9d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}