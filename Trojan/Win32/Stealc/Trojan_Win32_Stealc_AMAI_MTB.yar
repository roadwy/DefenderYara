
rule Trojan_Win32_Stealc_AMAI_MTB{
	meta:
		description = "Trojan:Win32/Stealc.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 31 18 6a 00 e8 [0-28] 83 45 ec 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}