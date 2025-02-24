
rule Trojan_BAT_Taskun_MBQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {78 00 6c 00 00 09 4c 00 6f 00 61 00 64 00 00 23 53 00 65 00 67 00 6f 00 65 00 20 00 55 00 49 00 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}