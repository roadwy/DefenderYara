
rule Trojan_BAT_Stealer_USV_MTB{
	meta:
		description = "Trojan:BAT/Stealer.USV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 55 53 45 52 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 53 79 73 74 65 6d 5c 6a 6f 62 73 } //1 C:\Users\USER\AppData\Roaming\System\jobs
		$a_81_1 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //1 HideModuleNameAttribute
		$a_81_2 = {41 73 73 65 6d 62 6c 79 54 72 61 64 65 6d 61 72 6b 41 74 74 72 69 62 75 74 65 } //1 AssemblyTrademarkAttribute
		$a_81_3 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //1 NewLateBinding
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}