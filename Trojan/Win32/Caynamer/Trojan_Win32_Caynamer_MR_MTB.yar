
rule Trojan_Win32_Caynamer_MR_MTB{
	meta:
		description = "Trojan:Win32/Caynamer.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d8 85 40 00 90 02 02 e8 90 02 0e 31 90 02 03 81 90 02 0c 09 90 01 01 39 90 01 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}