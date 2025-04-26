
rule Trojan_Win32_Rhadamanthys_DCP_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.DCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 08 8b 7c 24 0c 81 f1 1d 19 22 f0 81 f7 16 c6 8b 1d 09 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}