
rule Trojan_Win32_StealC_GJ_MTB{
	meta:
		description = "Trojan:Win32/StealC.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 57 8d 14 06 e8 be ff ff ff 30 02 46 59 3b 75 10 72 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}