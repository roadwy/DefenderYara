
rule Trojan_Win32_GenCBL_PACU_MTB{
	meta:
		description = "Trojan:Win32/GenCBL.PACU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 f6 d6 68 ac 1c 01 9e 41 80 f6 27 41 d0 ce 41 fe ce 41 80 f6 19 45 32 de 48 81 ee 02 00 00 00 66 44 89 36 } //00 00 
	condition:
		any of ($a_*)
 
}