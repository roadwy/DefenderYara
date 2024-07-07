
rule Trojan_BAT_Taskun_NT_MTB{
	meta:
		description = "Trojan:BAT/Taskun.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 20 40 79 1e 53 5a 20 90 01 03 2d 61 38 90 01 03 ff 7e 90 01 03 04 02 11 06 16 11 04 1a 59 28 90 01 03 0a 11 06 a5 90 01 03 1b 0b 11 07 20 90 01 03 65 5a 20 90 01 03 f8 61 38 90 01 03 ff 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}