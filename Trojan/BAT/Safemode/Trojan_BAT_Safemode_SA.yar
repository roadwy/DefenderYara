
rule Trojan_BAT_Safemode_SA{
	meta:
		description = "Trojan:BAT/Safemode.SA,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 } //1 bcdedit
		$a_00_1 = {2f 00 73 00 65 00 74 00 } //1 /set
		$a_00_2 = {73 00 61 00 66 00 65 00 62 00 6f 00 6f 00 74 00 } //1 safeboot
		$a_00_3 = {6d 00 69 00 6e 00 69 00 6d 00 61 00 6c 00 } //1 minimal
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}