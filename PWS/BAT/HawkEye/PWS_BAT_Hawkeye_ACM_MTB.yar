
rule PWS_BAT_Hawkeye_ACM_MTB{
	meta:
		description = "PWS:BAT/Hawkeye.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 88 00 00 00 91 1f 79 59 2b ed 11 04 1f 7e 91 1c 5b 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}