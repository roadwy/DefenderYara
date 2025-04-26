
rule Trojan_Win32_StealC_NC_MTB{
	meta:
		description = "Trojan:Win32/StealC.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {60 e8 00 00 00 00 5d 81 ed 10 00 00 00 81 ed 1c 55 be 00 e9 04 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}