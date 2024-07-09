
rule Trojan_BAT_Heracles_MBZB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 08 5d 13 ?? 07 11 ?? 91 11 ?? 09 1f ?? 5d 91 61 13 ?? 1f ?? 13 } //1
		$a_01_1 = {09 11 06 91 11 08 11 04 1f 16 5d 91 61 13 0c 1f 0d 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}