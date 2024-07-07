
rule Trojan_Win32_Fauppod_SPUO_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.SPUO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_81_0 = {49 68 7a 70 68 65 75 6c 64 53 } //2 IhzpheuldS
		$a_01_1 = {49 68 7a 70 68 65 75 6c 64 53 } //2 IhzpheuldS
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}