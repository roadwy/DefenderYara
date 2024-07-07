
rule Trojan_BAT_Genkryptik_UYRE_MTB{
	meta:
		description = "Trojan:BAT/Genkryptik.UYRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 02 26 16 02 73 1b 00 00 0a 0a 06 28 90 01 03 06 0b dd 0d 00 00 00 06 39 06 00 00 00 06 28 90 01 03 06 dc 07 2a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}