
rule Trojan_Win32_Copak_GPA_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 8b 5d 00 [0-30] 31 [0-3f] ff 00 00 00 [0-5f] 81 ?? f4 01 00 00 75 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}