
rule Trojan_Win32_Detplock_RPX_MTB{
	meta:
		description = "Trojan:Win32/Detplock.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {21 fb 4f 31 11 29 ff 81 ef 01 00 00 00 01 fb 41 81 eb 01 00 00 00 } //1
		$a_01_1 = {8b 12 89 ff 81 e2 ff 00 00 00 09 df 29 db 29 db 46 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}