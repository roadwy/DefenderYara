
rule Trojan_Win32_Marte_AMR_MTB{
	meta:
		description = "Trojan:Win32/Marte.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 b0 80 a8 41 00 1c 40 3d 04 30 07 00 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}