
rule Trojan_BAT_Redline_RS_MTB{
	meta:
		description = "Trojan:BAT/Redline.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 18 5b 8d 0d 00 00 01 2b 1e 16 0c 2b 1d 07 08 18 5b 02 08 18 6f 14 00 00 0a 1f 10 28 15 00 00 0a 9c 08 18 58 0c 2b 03 0b 2b df 08 06 32 02 2b 05 2b db 0a 2b ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}