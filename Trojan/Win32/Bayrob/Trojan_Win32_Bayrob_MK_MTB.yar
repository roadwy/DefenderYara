
rule Trojan_Win32_Bayrob_MK_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 11 29 d1 31 f6 8a 1c 32 88 1c 30 46 39 f1 75 f5 01 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}