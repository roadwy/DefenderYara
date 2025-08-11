
rule Trojan_BAT_Taskun_BAB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 8f 61 00 00 01 25 47 03 61 d2 52 07 17 58 0b 07 06 8e 69 32 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}