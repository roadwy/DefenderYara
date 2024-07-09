
rule Trojan_Win32_Stealc_NCS_MTB{
	meta:
		description = "Trojan:Win32/Stealc.NCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 05 e8 e1 1e 00 00 8b 35 ?? ?? ?? ?? 33 ff 8a 06 3a c3 74 12 3c ?? 74 01 47 56 e8 f5 f5 ff ff 59 8d 74 06 ?? eb e8 8d 04 bd } //5
		$a_01_1 = {76 63 61 70 69 2e 65 78 65 } //1 vcapi.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}