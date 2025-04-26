
rule Trojan_Win32_Banker_MBS_MTB{
	meta:
		description = "Trojan:Win32/Banker.MBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {36 35 34 36 34 35 72 72 72 72 40 6d 61 69 6c 2e 72 75 00 37 36 37 38 37 6a 68 6a 68 40 6d 61 69 6c 2e 72 75 00 73 6d 74 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}