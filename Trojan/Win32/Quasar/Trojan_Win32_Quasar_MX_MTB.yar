
rule Trojan_Win32_Quasar_MX_MTB{
	meta:
		description = "Trojan:Win32/Quasar.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 6f 20 00 00 0a 5d 6f 21 00 00 0a 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}