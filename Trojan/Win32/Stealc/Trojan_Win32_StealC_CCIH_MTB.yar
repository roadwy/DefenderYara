
rule Trojan_Win32_StealC_CCIH_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 3a 8d 42 ?? 30 41 ?? 42 83 fa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}