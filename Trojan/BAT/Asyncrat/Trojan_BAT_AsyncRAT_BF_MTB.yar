
rule Trojan_BAT_AsyncRAT_BF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 fe 0e 03 00 fe 0c 03 00 14 14 14 28 } //2
		$a_01_1 = {0a 0d 09 02 16 02 8e 69 6f } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*4) >=6
 
}