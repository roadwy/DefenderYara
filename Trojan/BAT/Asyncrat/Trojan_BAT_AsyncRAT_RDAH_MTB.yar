
rule Trojan_BAT_AsyncRAT_RDAH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {a2 25 17 d0 02 00 00 1b 28 17 00 00 0a a2 6f 18 00 00 0a 06 18 8d 0c 00 00 01 25 16 03 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}