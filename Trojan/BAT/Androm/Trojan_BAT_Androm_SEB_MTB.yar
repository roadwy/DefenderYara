
rule Trojan_BAT_Androm_SEB_MTB{
	meta:
		description = "Trojan:BAT/Androm.SEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5f 62 60 20 b4 d5 fd 61 59 20 ca a9 00 00 20 ab a9 00 00 59 5f 64 60 72 24 06 00 70 a2 28 17 00 00 0a d0 03 00 00 02 28 14 00 00 0a 6f 6b 00 00 0a 73 6c 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}