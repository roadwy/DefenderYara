
rule Trojan_Win32_Emotet_GQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_80_0 = {45 53 45 54 20 53 74 75 70 69 64 } //ESET Stupid  10
	condition:
		((#a_80_0  & 1)*10) >=10
 
}