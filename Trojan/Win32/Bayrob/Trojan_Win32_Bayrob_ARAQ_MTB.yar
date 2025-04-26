
rule Trojan_Win32_Bayrob_ARAQ_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 37 30 06 ff 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}