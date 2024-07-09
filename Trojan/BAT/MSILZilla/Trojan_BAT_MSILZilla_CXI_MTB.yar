
rule Trojan_BAT_MSILZilla_CXI_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.CXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 18 5b 06 09 18 6f ?? ?? ?? ?? 1f 10 28 1c ?? ?? ?? 9c 09 18 58 0d 09 07 32 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}