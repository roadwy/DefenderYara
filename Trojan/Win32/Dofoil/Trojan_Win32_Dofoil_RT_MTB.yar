
rule Trojan_Win32_Dofoil_RT_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 03 e8 90 01 04 30 02 57 ff d6 57 ff 15 90 01 04 57 57 57 ff 15 90 01 04 68 90 01 04 57 ff 15 90 01 04 43 3b 90 01 02 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}