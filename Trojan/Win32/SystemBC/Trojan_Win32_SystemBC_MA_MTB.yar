
rule Trojan_Win32_SystemBC_MA_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff cc 31 00 3f 08 f4 f5 14 50 05 81 42 b8 18 12 2e 35 ce 99 5a 0f f0 d8 68 ed 19 f7 42 a8 34 cb } //00 00 
	condition:
		any of ($a_*)
 
}