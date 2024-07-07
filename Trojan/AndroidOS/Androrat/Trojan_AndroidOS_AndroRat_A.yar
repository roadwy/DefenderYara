
rule Trojan_AndroidOS_AndroRat_A{
	meta:
		description = "Trojan:AndroidOS/AndroRat.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 5f 63 61 70 5f 73 63 72 65 65 6e } //2 start_cap_screen
		$a_00_1 = {73 6d 73 6c 67 3d } //1 smslg=
		$a_00_2 = {75 6e 73 65 74 4e 6f 74 69 66 } //2 unsetNotif
		$a_00_3 = {73 6d 73 4d 6f 6e 69 74 65 72 3c } //2 smsMoniter<
		$a_00_4 = {73 65 74 5f 45 6e 62 67 70 73 53 65 72 76 69 63 65 } //1 set_EnbgpsService
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1) >=7
 
}