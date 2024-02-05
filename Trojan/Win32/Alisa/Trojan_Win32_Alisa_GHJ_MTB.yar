
rule Trojan_Win32_Alisa_GHJ_MTB{
	meta:
		description = "Trojan:Win32/Alisa.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {b0 65 88 44 24 90 01 01 88 44 24 90 01 01 88 44 24 90 01 01 8d 44 24 90 01 01 50 51 c6 44 24 90 01 01 43 c6 44 24 90 01 01 72 c6 44 24 90 01 01 61 c6 44 24 90 01 01 74 c6 44 24 90 01 01 45 c6 44 24 90 01 01 76 c6 44 24 90 01 01 6e c6 44 24 90 01 01 74 c6 44 24 90 01 01 41 88 5c 24 90 00 } //01 00 
		$a_80_1 = {43 68 37 44 65 6d 6f 36 2e 45 58 45 } //Ch7Demo6.EXE  00 00 
	condition:
		any of ($a_*)
 
}