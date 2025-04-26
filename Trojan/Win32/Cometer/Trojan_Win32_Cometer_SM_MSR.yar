
rule Trojan_Win32_Cometer_SM_MSR{
	meta:
		description = "Trojan:Win32/Cometer.SM!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 94 85 0c fe ff ff 0f b6 41 fc c0 e2 02 0f b6 84 85 0c fe ff ff c0 e8 04 0a d0 88 57 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}