
rule Ransom_Win32_Paradise_BN_MTB{
	meta:
		description = "Ransom:Win32/Paradise.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {70 6f 73 74 67 } //postg  01 00 
		$a_80_1 = {73 74 6f 72 65 2e 65 78 65 } //store.exe  01 00 
		$a_80_2 = {62 65 73 31 30 } //bes10  01 00 
		$a_80_3 = {74 61 72 69 64 64 } //taridd  01 00 
		$a_80_4 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 26 20 64 65 6c 20 22 25 73 22 } //ping 127.0.0.1 && del "%s"  01 00 
		$a_80_5 = {68 74 74 70 3a 2f 2f 70 72 74 2d 72 65 63 6f 76 65 72 79 2e 73 75 70 70 6f 72 74 2f 63 68 61 74 2f } //http://prt-recovery.support/chat/  00 00 
	condition:
		any of ($a_*)
 
}