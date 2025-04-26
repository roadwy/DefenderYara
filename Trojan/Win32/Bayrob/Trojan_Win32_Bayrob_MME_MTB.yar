
rule Trojan_Win32_Bayrob_MME_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MME!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 07 50 e8 ea fb ff ff 59 e8 ed 68 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}