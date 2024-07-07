
rule Trojan_Win32_Qshell_MR_MTB{
	meta:
		description = "Trojan:Win32/Qshell.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 02 8b 45 90 01 01 05 90 02 04 03 90 02 02 8b 90 02 02 31 90 01 01 83 90 02 03 83 90 02 03 8b 90 02 02 3b 90 02 02 90 18 8b 90 02 02 8b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}