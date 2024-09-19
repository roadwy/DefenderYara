
rule Trojan_BAT_AsyncRAT_BG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 0d 09 14 14 14 } //2 ഁᐉᐔ
		$a_01_1 = {06 0d 09 02 16 02 8e 69 6f } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*4) >=6
 
}