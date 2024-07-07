
rule Trojan_BAT_Tedy_PTBT_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PTBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 6f 22 00 00 0a 26 07 6f 23 00 00 0a 6f 24 00 00 0a 0c 08 17 8d 31 00 00 01 25 16 1f 2d 9d 6f 25 00 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}