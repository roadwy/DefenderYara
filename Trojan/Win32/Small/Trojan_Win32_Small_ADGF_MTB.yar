
rule Trojan_Win32_Small_ADGF_MTB{
	meta:
		description = "Trojan:Win32/Small.ADGF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c8 8d 04 3e 8d 04 87 03 cf 8a 04 18 46 32 45 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}