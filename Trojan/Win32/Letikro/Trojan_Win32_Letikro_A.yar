
rule Trojan_Win32_Letikro_A{
	meta:
		description = "Trojan:Win32/Letikro.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {21 74 69 63 6b 69 74 21 } //2 !tickit!
		$a_01_1 = {21 73 74 6f 72 61 67 65 21 } //2 !storage!
		$a_01_2 = {6c 65 67 6f 32 2e 69 6e 69 } //1 lego2.ini
		$a_01_3 = {4c 45 47 4f 5f 4d 55 54 45 58 32 } //1 LEGO_MUTEX2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}