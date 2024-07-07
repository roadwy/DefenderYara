
rule Trojan_Win32_Marte_CCHZ_MTB{
	meta:
		description = "Trojan:Win32/Marte.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 68 70 02 00 00 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}