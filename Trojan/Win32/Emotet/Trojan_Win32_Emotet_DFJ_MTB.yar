
rule Trojan_Win32_Emotet_DFJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {03 c1 99 8b cf f7 f9 8b 45 e8 8a 4c 15 00 30 08 } //01 00 
		$a_81_1 = {41 47 7a 6a 32 47 48 6d 58 51 73 75 5a 71 74 67 64 35 52 50 6a 47 6a 6a 39 6e 42 50 53 4c 39 6c 35 41 56 36 64 } //00 00 
	condition:
		any of ($a_*)
 
}