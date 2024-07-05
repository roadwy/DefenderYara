
rule Trojan_Win32_Zusy_RW_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 72 cb bd 9e 9f 6f 59 ec 4e 18 f3 94 ee } //01 00 
		$a_01_1 = {f1 8c 00 be 7b d7 4c 4e 31 63 58 22 74 db 35 3d af 7c 0b da dd 1e } //00 00 
	condition:
		any of ($a_*)
 
}