
rule Trojan_MacOS_AMOS_HAB_MTB{
	meta:
		description = "Trojan:MacOS/AMOS.HAB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 08 33 85 ?? ?? ff ff 88 c1 8b 85 ?? ?? ff ff 88 8c } //20
		$a_01_1 = {40 5f 5f 5a 4e 34 6d 6c 63 67 34 70 72 6e 67 45 6a } //5 @__ZN4mlcg4prngEj
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*5) >=25
 
}