
rule Trojan_BAT_Taskun_AMAT_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 95 d2 61 d2 9c 11 ?? 17 6a 58 13 } //2
		$a_03_1 = {8e 69 6a 5d d4 91 58 11 [0-0a] 95 58 20 ff 00 00 00 5f } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}