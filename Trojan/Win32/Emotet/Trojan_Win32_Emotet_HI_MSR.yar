
rule Trojan_Win32_Emotet_HI_MSR{
	meta:
		description = "Trojan:Win32/Emotet.HI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 63 00 76 00 78 00 67 00 64 00 66 00 61 00 64 00 65 00 2e 00 73 00 78 00 63 00 61 00 73 00 65 00 } //1 C:\ProgramData\cvxgdfade.sxcase
	condition:
		((#a_01_0  & 1)*1) >=1
 
}