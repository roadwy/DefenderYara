
rule Trojan_BAT_Remcos_RDP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {a2 28 bd 00 00 0a 75 33 00 00 01 0b 07 6f be 00 00 0a 18 9a 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}