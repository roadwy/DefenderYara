
rule Adware_BAT_Dotdo_SR_MSR{
	meta:
		description = "Adware:BAT/Dotdo.SR!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fa 25 33 00 16 00 00 01 00 00 00 11 00 00 00 02 00 00 00 03 00 00 00 02 00 00 00 11 00 00 00 0c 00 00 00 01 00 00 00 01 00 00 00 02 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}