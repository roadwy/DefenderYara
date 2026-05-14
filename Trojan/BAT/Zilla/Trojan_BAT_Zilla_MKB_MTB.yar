
rule Trojan_BAT_Zilla_MKB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 7e 0a 00 00 04 72 2b 01 00 70 28 48 00 00 0a 6f 49 00 00 0a 73 37 00 00 0a 6f 38 00 00 0a 72 95 01 00 70 28 10 00 00 06 72 ff 01 00 70 72 ad 00 00 70 6f 4a 00 00 0a 17 8d 55 00 00 01 25 16 1f 2c 9d 6f 4b 00 00 0a 0c 08 39 fc } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}