
rule TrojanDropper_BAT_FormBook_SJ_MTB{
	meta:
		description = "TrojanDropper:BAT/FormBook.SJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 28 05 00 00 06 0c 08 28 07 00 00 06 00 28 12 00 00 0a 28 13 00 00 0a 13 04 12 04 fe 16 0d 00 00 01 6f 14 00 00 0a 72 09 00 00 70 28 09 00 00 0a 28 15 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}